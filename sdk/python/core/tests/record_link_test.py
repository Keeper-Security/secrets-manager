import json
import logging
import os
import tempfile
import unittest

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock, utils
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperRecordLink
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import FileKeyValueStorage


def plain_link(payload, path=None, record_uid="RU_test"):
    """Build a link whose data is base64 of the given plain JSON payload."""
    return KeeperRecordLink({
        "recordUid": record_uid,
        "data": utils.bytes_to_base64(json.dumps(payload).encode()),
        "path": path
    })


def encrypted_link(payload, key, path=None, record_uid="RU_test"):
    """Build a link whose data is base64 of the payload encrypted with AES-256-GCM."""
    ciphertext = CryptoUtils.encrypt_aes(json.dumps(payload).encode(), key)
    return KeeperRecordLink({
        "recordUid": record_uid,
        "data": utils.bytes_to_base64(ciphertext),
        "path": path
    })


class RecordLinkTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

        logger = logging.getLogger("ksm")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        while logger.hasHandlers():
            logger.removeHandler(logger.handlers[0])
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        formatter = logging.Formatter(f'%(asctime)s %(name)s  %(levelname)s: %(message)s')
        handler.setFormatter(formatter)

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_boolean_accessors_read_plain_json(self):
        """Boolean accessors read the decoded plain JSON; absent keys default to False."""

        link = plain_link({"is_admin": True, "rotation": True, "connections": False})

        self.assertTrue(link.is_admin_user(), "is_admin true should read true")
        self.assertTrue(link.allows_rotation(), "rotation true should read true")
        self.assertFalse(link.allows_connections(), "connections false should read false")

        # Absent keys must default to False
        self.assertFalse(link.allows_port_forwards(), "absent key must default to False")
        self.assertFalse(link.is_launch_credential(), "absent key must default to False")
        self.assertFalse(link.is_iam_user(), "absent key must default to False")
        self.assertFalse(link.belongs_to(), "absent key must default to False")
        self.assertFalse(link.no_update_services(), "absent key must default to False")

    def test_version_and_decoded_data(self):
        """Integer version, decoded data and the readable-JSON heuristic."""

        link = plain_link({"version": 3, "is_admin": False})
        self.assertEqual(3, link.get_link_data_version())
        decoded = link.get_decoded_data()
        self.assertIsNotNone(decoded, "plain JSON data should decode")
        self.assertTrue(decoded.startswith("{"), "decoded data is the raw JSON")
        self.assertTrue(link.has_readable_data(), "JSON payload is readable")

        # Non-JSON (but valid base64) decoded content is not "readable"
        raw = KeeperRecordLink({
            "recordUid": "RU",
            "data": utils.bytes_to_base64(b"not json at all"),
            "path": None
        })
        self.assertFalse(raw.has_readable_data(), "plain text without JSON markers is not readable")
        self.assertIsNone(raw.get_link_data_version(), "no version in non-JSON data")

        # Invalid base64 decodes to None, never raises
        bad = KeeperRecordLink({"recordUid": "RU", "data": "!!! not base64 !!!", "path": None})
        self.assertIsNone(bad.get_decoded_data())
        self.assertIsNone(bad.get_link_data())

    def test_might_be_encrypted_by_path(self):
        """might_be_encrypted is gated to the known encrypted paths only."""

        self.assertTrue(plain_link({}, path="ai_settings").might_be_encrypted())
        self.assertTrue(plain_link({}, path="jit_settings").might_be_encrypted())
        self.assertFalse(plain_link({}, path="meta").might_be_encrypted(),
                         "meta links carry plain JSON")
        self.assertFalse(plain_link({}, path="something_else").might_be_encrypted(),
                         "unknown path must not be assumed encrypted")
        self.assertFalse(plain_link({}, path=None).might_be_encrypted())

    def test_get_decrypted_data_roundtrip(self):
        """AES-256-GCM decrypt round-trip with the record key; wrong/absent key gives None."""

        key = CryptoUtils.generate_random_bytes(32)
        payload = {"enabled": True, "ttl": 3600}
        link = encrypted_link(payload, key, path="jit_settings")

        decrypted = link.get_decrypted_data(key)
        self.assertIsNotNone(decrypted, "correct key decrypts")
        self.assertEqual(payload, json.loads(decrypted), "decrypts to the original plaintext")

        self.assertIsNone(link.get_decrypted_data(None), "no key gives None")

        wrong_key = CryptoUtils.generate_random_bytes(32)
        self.assertIsNone(link.get_decrypted_data(wrong_key),
                          "wrong key fails to decrypt and gives None, not an exception")

    def test_get_link_data_plain_and_encrypted(self):
        """get_link_data auto-detects plain JSON vs encrypted data."""

        plain = plain_link({"aiEnabled": True}, path="ai_settings")
        data = plain.get_link_data()
        self.assertIsNotNone(data, "plain JSON parses without a key")
        self.assertTrue(data.get("aiEnabled"))

        key = CryptoUtils.generate_random_bytes(32)
        enc = encrypted_link({"enabled": True}, key, path="jit_settings")
        self.assertIsNone(enc.get_link_data(), "encrypted without key gives None")
        data = enc.get_link_data(key)
        self.assertIsNotNone(data, "encrypted with key parses")
        self.assertTrue(data.get("enabled"))

    def test_settings_path_filters(self):
        """Settings accessors are gated to the matching path."""

        key = CryptoUtils.generate_random_bytes(32)
        ai = plain_link({"aiEnabled": True}, path="ai_settings")
        jit = plain_link({"enabled": True}, path="jit_settings")

        self.assertIsNotNone(ai.get_ai_settings_data(key), "ai path returns ai settings")
        self.assertIsNone(ai.get_jit_settings_data(key), "ai path is not jit")
        self.assertIsNotNone(jit.get_jit_settings_data(key), "jit path returns jit settings")
        self.assertIsNone(jit.get_ai_settings_data(key), "jit path is not ai")

        # Generic accessor matches any path
        self.assertIsNotNone(ai.get_settings_for_path("ai_settings"),
                             "generic accessor matches the path")
        self.assertIsNone(ai.get_settings_for_path("other"),
                          "generic accessor returns None for a non-matching path")

    def test_record_get_links_end_to_end(self):
        """Record.get_links() builds typed links from the raw links field, which is unchanged."""

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name)
                )

                res = mock.Response()

                linked_record = res.add_record(title="Linked User", record_type='login')
                linked_record.field("login", "linkeduser")

                links_data = [
                    # meta self-link (plain JSON, live shape)
                    {"recordUid": "mainUid", "path": "meta",
                     "data": utils.bytes_to_base64(json.dumps(
                         {"allowedSettings": {"rotation": True}, "version": 1}).encode())},
                    # credential link to another record
                    {"recordUid": linked_record.uid, "path": None,
                     "data": utils.bytes_to_base64(json.dumps(
                         {"is_admin": True, "is_launch_credential": True}).encode())},
                    # pure reference link (no data)
                    {"recordUid": "referencedUid", "data": None, "path": None},
                    # malformed entry without recordUid is kept raw but skipped by get_links()
                    {"data": None, "path": None},
                ]
                main_record = res.add_record(
                    title="Main Record",
                    record_type='login',
                    links=links_data
                )
                main_record.field("login", "mainuser")
                main_record.field("password", "mainpass")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()

                main_rec = next((r for r in records if r.title == "Main Record"), None)
                self.assertIsNotNone(main_rec, "Main record not found")

                # The raw links field is unchanged (back-compat)
                self.assertEqual(4, len(main_rec.links), "raw links list keeps all entries")
                self.assertEqual(links_data, main_rec.links, "raw links are untouched dicts")

                links = main_rec.get_links()
                self.assertEqual(3, len(links), "entry without recordUid is skipped")
                self.assertTrue(all(isinstance(link, KeeperRecordLink) for link in links))

                meta = links[0]
                self.assertEqual("mainUid", meta.record_uid)
                self.assertEqual("meta", meta.path)
                self.assertTrue(meta.allows_rotation(), "typed link decodes its data")
                self.assertEqual(1, meta.get_link_data_version())

                cred = links[1]
                self.assertEqual(linked_record.uid, cred.record_uid)
                self.assertTrue(cred.is_admin_user())
                self.assertTrue(cred.is_launch_credential())

                ref = links[2]
                self.assertEqual("referencedUid", ref.record_uid)
                self.assertIsNone(ref.get_link_data())
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_string_encoded_values_are_not_coerced(self):
        """String-encoded values are NOT coerced to bool/int (Java/Rust parity)."""

        link = plain_link({"is_admin": "true", "rotation": "false", "version": "3"})
        self.assertFalse(link.is_admin_user(), 'string "true" is not coerced to bool')
        self.assertFalse(link.allows_rotation(), 'string "false" stays falsey')
        self.assertIsNone(link.get_link_data_version(), 'string "3" is not coerced to int')

        # Real JSON bool/number ARE read
        typed = plain_link({"is_admin": True, "version": 3})
        self.assertTrue(typed.is_admin_user())
        self.assertEqual(3, typed.get_link_data_version())

        # Python quirk: True is an int, but must not count as a version
        bool_version = plain_link({"version": True})
        self.assertIsNone(bool_version.get_link_data_version(),
                          "boolean version is not an integer version")

    def test_has_encrypted_data_detection(self):
        """has_encrypted_data inspects the content: ciphertext yes, printable text/JSON no."""

        key = CryptoUtils.generate_random_bytes(32)
        ciphertext = CryptoUtils.encrypt_aes(b"some secret bytes", key)
        enc = KeeperRecordLink({
            "recordUid": "RU",
            "data": utils.bytes_to_base64(ciphertext),
            "path": None
        })
        self.assertTrue(enc.has_encrypted_data(), "ciphertext is detected as encrypted")

        text = KeeperRecordLink({
            "recordUid": "RU",
            "data": utils.bytes_to_base64(b"just plain readable text, not json"),
            "path": None
        })
        self.assertFalse(text.has_encrypted_data(), "printable text is not flagged encrypted")

        self.assertFalse(plain_link({"a": 1}).has_encrypted_data(),
                         "JSON is not flagged encrypted")

        no_data = KeeperRecordLink({"recordUid": "RU", "data": None, "path": None})
        self.assertFalse(no_data.has_encrypted_data(), "no data is not flagged encrypted")

    def test_get_settings_for_path_encrypted(self):
        """Generic settings accessor decrypts an encrypted payload for a matching path."""

        key = CryptoUtils.generate_random_bytes(32)
        link = encrypted_link({"customSetting": 42}, key, path="custom_settings")

        data = link.get_settings_for_path("custom_settings", key)
        self.assertIsNotNone(data, "matching path with key decrypts")
        self.assertEqual(42, data.get("customSetting"))
        self.assertIsNone(link.get_settings_for_path("other", key), "non-matching path gives None")

    def test_meta_link_live_shape(self):
        """meta self-links: permission booleans fall back to the nested allowedSettings."""

        link = plain_link({
            "allowedSettings": {
                "rotation": True,
                "connections": True,
                "portForwards": True,
                "sessionRecording": True,
                "typescriptRecording": False,
                "aiEnabled": True,
                "aiSessionTerminate": True,
                "remoteBrowserIsolation": True
            },
            "rotateOnTermination": False,
            "version": 1,
            "no_update_services": True
        }, path="meta")

        # Permission booleans read from allowedSettings when absent at the top level
        self.assertTrue(link.allows_rotation())
        self.assertTrue(link.allows_connections())
        self.assertTrue(link.allows_port_forwards())
        self.assertTrue(link.allows_session_recording())
        self.assertFalse(link.allows_typescript_recording())
        self.assertTrue(link.allows_remote_browser_isolation())
        self.assertTrue(link.ai_enabled())
        self.assertTrue(link.ai_session_terminate())

        # Top-level fields
        self.assertFalse(link.rotates_on_termination())
        self.assertEqual(1, link.get_link_data_version())
        self.assertTrue(link.no_update_services())

        # Dict accessors
        allowed = link.get_allowed_settings()
        self.assertTrue(allowed.get("rotation"))
        meta = link.get_meta_data()
        self.assertIsNotNone(meta, "meta data parses without a key")
        self.assertEqual(1, meta.get("version"))
        self.assertIsNone(plain_link({}, path=None).get_meta_data(),
                          "get_meta_data is gated to path meta")

    def test_credential_link_live_shape(self):
        """Credential links: user flags and the nested rotation_settings object."""

        link = plain_link({
            "is_admin": True,
            "is_iam_user": False,
            "belongs_to": True,
            "is_launch_credential": True,
            "rotation_settings": {
                "schedule": "",
                "pwd_complexity": "ZmFrZS1jb21wbGV4aXR5",
                "disabled": False,
                "noop": False,
                "saas_record_uid_list": []
            }
        })

        self.assertTrue(link.is_admin_user())
        self.assertFalse(link.is_iam_user())
        self.assertTrue(link.belongs_to())
        self.assertTrue(link.is_launch_credential())

        rotation_settings = link.get_rotation_settings()
        self.assertIsNotNone(rotation_settings)
        self.assertEqual("", rotation_settings.get("schedule"))
        self.assertFalse(rotation_settings.get("disabled"))
        self.assertEqual([], rotation_settings.get("saas_record_uid_list"))

        self.assertIsNone(plain_link({"is_admin": True}).get_rotation_settings(),
                          "absent rotation_settings gives None")

    def test_data_less_reference_link(self):
        """Pure reference links (data null) answer all accessors with False/None."""

        link = KeeperRecordLink({"recordUid": "RU_ref", "data": None, "path": None})

        self.assertEqual("RU_ref", link.record_uid)
        self.assertFalse(link.is_admin_user())
        self.assertFalse(link.allows_rotation())
        self.assertIsNone(link.get_link_data_version())
        self.assertIsNone(link.get_decoded_data())
        self.assertIsNone(link.get_decrypted_data(CryptoUtils.generate_random_bytes(32)))
        self.assertIsNone(link.get_link_data())
        self.assertEqual({}, link.get_allowed_settings())
        self.assertIsNone(link.get_rotation_settings())
        self.assertFalse(link.has_readable_data())
        self.assertFalse(link.has_encrypted_data())

    def test_ai_settings_live_shape(self):
        """ai_settings links decrypt to the current riskLevels payload."""

        key = CryptoUtils.generate_random_bytes(32)
        payload = {
            "version": "v1.0.0",
            "riskLevels": {
                "critical": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": True},
                "high": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": True},
                "medium": {"tags": {"allow": [], "deny": []}, "aiSessionTerminate": True},
                "low": {"tags": {"allow": []}, "aiSessionTerminate": False}
            }
        }
        link = encrypted_link(payload, key, path="ai_settings")

        data = link.get_ai_settings_data(key)
        self.assertIsNotNone(data)
        self.assertEqual(payload, data, "nested riskLevels structure is preserved")

        # The live version field is a string here, so the integer accessor yields None
        self.assertIsNone(link.get_link_data_version())

    def test_jit_settings_live_shape(self):
        """jit_settings links decrypt to the current elevation payload."""

        key = CryptoUtils.generate_random_bytes(32)
        payload = {
            "createEphemeral": True,
            "elevate": True,
            "elevationMethod": "group",
            "elevationString": "arn:aws",
            "baseDistinguishedName": ""
        }
        link = encrypted_link(payload, key, path="jit_settings")

        data = link.get_jit_settings_data(key)
        self.assertIsNotNone(data)
        self.assertEqual(payload, data)

    def test_losslessness(self):
        """Unknown link keys and payload fields are preserved in raw and get_link_data."""

        payload = {"is_admin": True, "futureField": {"nested": [1, 2, 3]}}
        link_dict = {
            "recordUid": "RU",
            "data": utils.bytes_to_base64(json.dumps(payload).encode()),
            "path": None,
            "futureLinkKey": "kept"
        }
        link = KeeperRecordLink(link_dict)

        self.assertEqual(link_dict, link.raw, "raw keeps the original dict untouched")
        self.assertEqual("kept", link.raw.get("futureLinkKey"))

        data = link.get_link_data()
        self.assertEqual({"nested": [1, 2, 3]}, data.get("futureField"),
                         "unknown payload fields pass through get_link_data")

    def test_top_level_wins_over_allowed_settings(self):
        """A top-level boolean takes precedence over the allowedSettings fallback."""

        link = plain_link({
            "rotation": False,
            "allowedSettings": {"rotation": True}
        })
        self.assertFalse(link.allows_rotation(), "top-level value wins")

        only_nested = plain_link({"allowedSettings": {"rotation": True}})
        self.assertTrue(only_nested.allows_rotation(), "fallback applies when top level is absent")

    def test_ciphertext_with_json_like_first_byte(self):
        """Ciphertext coincidentally starting with "{" or "[" still decrypts.

        AES-GCM output starts with the random IV, so ~2/256 of encrypted links
        begin with a JSON marker. The plain-JSON fast path must fall through to
        decryption when its parse fails, instead of dropping the data.
        """

        key = CryptoUtils.generate_random_bytes(32)
        payload = {"createEphemeral": True, "elevate": True}

        for marker in (b"{", b"["):
            iv = marker + os.urandom(11)
            ciphertext = CryptoUtils.encrypt_aes(json.dumps(payload).encode(), key, iv=iv)
            link = KeeperRecordLink({
                "recordUid": "RU",
                "data": utils.bytes_to_base64(ciphertext),
                "path": "jit_settings"
            })

            decoded = link.get_decoded_data()
            self.assertEqual(marker.decode(), decoded[0],
                             "fixture must start with the JSON marker")

            self.assertEqual(payload, link.get_link_data(key),
                             "falls through to decryption despite the JSON-like first byte")
            self.assertEqual(payload, link.get_jit_settings_data(key),
                             "settings accessors benefit from the fall-through")
            self.assertEqual(payload, link.get_settings_for_path("jit_settings", key))
            self.assertIsNone(link.get_link_data(None),
                              "still None without a key")

        # The plain-JSON fast path is unaffected.
        self.assertEqual({"a": 1}, plain_link({"a": 1}).get_link_data())


if __name__ == '__main__':
    unittest.main()
