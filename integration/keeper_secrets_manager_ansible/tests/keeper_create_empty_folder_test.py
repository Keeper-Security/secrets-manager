import unittest
import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_helper.record import Record


class KeeperCreateEmptyFolderTest(unittest.TestCase):
    """
    Regression test for KSM-816 / GitHub issue #934.

    keeper_create fails when the target shared folder contains no records.
    create_secret() uses get_secrets(full_response=True) to look up the folder
    encryption key, but that endpoint only returns folders bundled with records.
    Empty folders are invisible to it, so the key is never found.
    """

    def test_create_secret_fails_on_empty_folder(self):
        """Reproduce: create_secret raises when the target folder has no records."""

        secrets_manager = SecretsManager(
            config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64())
        )

        # Empty response — no records, no folders.
        # Simulates what the backend returns when a KSM app has access to a
        # shared folder that contains zero records.
        empty_response = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(empty_response)
        secrets_manager.custom_post_function = queue.post_method

        record = Record(version="v3").create_from_field_list(
            record_type="login",
            title="Test Record",
            notes=None,
            fields=[],
            password_generate=False,
            password_complexity=None
        )
        record_create = record[0].get_record_create_obj()

        with pytest.raises(Exception) as exc_info:
            secrets_manager.create_secret("EMPTY_FOLDER_UID", record_create)

        assert "was not retrieved" in str(exc_info.value)
