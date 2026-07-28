package com.keepersecurity.secretsManager;

import com.keepersecurity.secretsManager.core.HiddenField;
import com.keepersecurity.secretsManager.core.KeeperRecord;
import com.keepersecurity.secretsManager.core.KeeperRecordData;
import com.keepersecurity.secretsManager.core.KeeperRecordField;
import com.keepersecurity.secretsManager.core.Login;
import com.keepersecurity.secretsManager.core.Multiline;
import com.keepersecurity.secretsManager.core.PamSetting;
import com.keepersecurity.secretsManager.core.PamSettings;
import com.keepersecurity.secretsManager.core.Password;
import com.keepersecurity.secretsManager.core.Text;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeeperCredentialMapperTest {

    private static final KeeperCredentialMapper.Log NOOP = new KeeperCredentialMapper.Log() {
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
    };

    private static final String UID = "ABCDABCDABCDABCDABCDAB"; // 22 chars

    private static KeeperRecord record(String uid, KeeperRecordData data) {
        return new KeeperRecord(new byte[32], uid, null, null, null, data, 0L, null, null);
    }

    /** Log sink that records messages so tests can assert on the emitted diagnostics. */
    private static final class CapturingLog implements KeeperCredentialMapper.Log {
        final List<String> warns = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        @Override public void warn(String message) { warns.add(message); }
        @Override public void error(String message) { errors.add(message); }
    }

    private static KeeperRecordData genericData(String type, List<KeeperRecordField> custom) {
        return new KeeperRecordData("Rec", type, new ArrayList<>(), new ArrayList<>(custom));
    }

    private static KeeperRecordData loginData(String title, String user, String pass, List<KeeperRecordField> custom) {
        List<KeeperRecordField> fields = new ArrayList<>();
        fields.add(new Login(user));
        fields.add(new Password(pass));
        return new KeeperRecordData(title, "login", fields, new ArrayList<>(custom));
    }

    private static KeeperRecordData pamUserData(String title, String user, String pass, List<KeeperRecordField> custom) {
        List<KeeperRecordField> fields = new ArrayList<>();
        fields.add(new Login(user));
        fields.add(new Password(pass));
        return new KeeperRecordData(title, "pamUser", fields, new ArrayList<>(custom));
    }

    @Test
    void parsesRecordUid() {
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId(UID);
        assertTrue(id.isUidLookup());
        assertEquals(UID, id.recordUid);
    }

    @Test
    void parsesTypeAndTitle() {
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId("login:MyLogin");
        assertFalse(id.isUidLookup());
        assertEquals("login", id.recType);
        assertEquals("MyLogin", id.recTitle);
    }

    @Test
    void parsesTitleOnly() {
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId(":MyLogin");
        assertFalse(id.isUidLookup());
        assertEquals("", id.recType);
        assertEquals("MyLogin", id.recTitle);
    }

    @Test
    void parsesTypeOnly() {
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId("login:");
        assertFalse(id.isUidLookup());
        assertEquals("login", id.recType);
        assertEquals("", id.recTitle);
    }

    @Test
    void rejectsBareColon() {
        assertThrows(RuntimeException.class, () -> KeeperCredentialMapper.parseCredId(":"));
    }

    @Test
    void rejectsMalformedUid() {
        assertThrows(RuntimeException.class, () -> KeeperCredentialMapper.parseCredId("too-short"));
    }

    @Test
    void mapsLoginUserAndPassword() {
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", Collections.emptyList()));
        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", NOOP);
        assertEquals("alice", out.get("user"));
        assertEquals("s3cret", out.get("pswd"));
    }

    @Test
    void mapsPamUserUserAndPassword() {
        KeeperRecord rec = record(UID, pamUserData("MyPamUser", "svc_acct", "p@mP4ss", Collections.emptyList()));
        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", NOOP);
        assertEquals("svc_acct", out.get("user"));
        assertEquals("p@mP4ss", out.get("pswd"));
    }

    @Test
    void mapsPamUserStandardFieldsAndPrefixedCustomFields() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new HiddenField("mid_pkey", null, null, new ArrayList<>(Arrays.asList("PRIVATEKEY"))));
        KeeperRecord rec = record(UID, pamUserData("MyPamUser", "svc_acct", "p@mP4ss", custom));

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", NOOP);

        assertEquals("svc_acct", out.get("user"));
        assertEquals("p@mP4ss", out.get("pswd"));
        assertEquals("PRIVATEKEY", out.get("pkey"));
    }

    @Test
    void mapsPrefixedCustomFieldsAndSkipsUnprefixed() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new HiddenField("mid_pkey", null, null, new ArrayList<>(Arrays.asList("PRIVATEKEY"))));
        custom.add(new Text("mid_client_id", null, null, new ArrayList<>(Arrays.asList("client-123"))));
        custom.add(new Multiline("mid_note", null, null, new ArrayList<>(Arrays.asList("line1\nline2"))));
        custom.add(new Text("client_secret", null, null, new ArrayList<>(Arrays.asList("nope"))));
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", custom));

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", NOOP);

        assertEquals("PRIVATEKEY", out.get("pkey"));
        assertEquals("client-123", out.get("client_id"));
        assertEquals("line1\nline2", out.get("note"));
        assertFalse(out.containsKey("client_secret"));
    }

    // Regression for the TX-DPS escalation: a record carrying a PAM field type (pamSettings) must
    // resolve its login credentials without throwing. Referencing PamSettings/PamSetting here also
    // breaks the build if the SDK pin is ever reverted below the version that added them (16.6.5+).
    @Test
    void toleratesPamSettingsFieldOnRecord() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new HiddenField("mid_pkey", null, null, new ArrayList<>(Arrays.asList("PRIVATEKEY"))));
        custom.add(new PamSettings(new PamSetting()));
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", custom));

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", NOOP);

        assertEquals("alice", out.get("user"));
        assertEquals("s3cret", out.get("pswd"));
        assertEquals("PRIVATEKEY", out.get("pkey"));
    }

    @Test
    void selectsByTypeAndTitleIgnoringPamSibling() {
        // full fetch returns a PAM record shared to the app alongside the target login
        List<KeeperRecordField> pamFields = new ArrayList<>();
        pamFields.add(new PamSettings(new PamSetting()));
        KeeperRecord pamRec = record("PAMPAMPAMPAMPAMPAMPAM1",
                new KeeperRecordData("Some PAM Machine", "pamMachine", new ArrayList<>(), pamFields));
        KeeperRecord loginRec = record(UID, loginData("MyLogin", "alice", "s3cret", Collections.emptyList()));

        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId("login:MyLogin");
        KeeperRecord selected = KeeperCredentialMapper.selectRecord(
                Arrays.asList(pamRec, loginRec), "login:MyLogin", id, NOOP);

        assertEquals(UID, selected.getRecordUid());
    }

    @Test
    void selectReturnsSingleUidMatch() {
        KeeperRecord loginRec = record(UID, loginData("MyLogin", "alice", "s3cret", Collections.emptyList()));
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId(UID);
        KeeperRecord selected = KeeperCredentialMapper.selectRecord(
                Collections.singletonList(loginRec), UID, id, NOOP);
        assertSame(loginRec, selected);
    }

    @Test
    void selectThrowsOnNoMatch() {
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId("login:Nonexistent");
        assertThrows(RuntimeException.class, () -> KeeperCredentialMapper.selectRecord(
                Collections.emptyList(), "login:Nonexistent", id, NOOP));
    }

    @Test
    void selectThrowsOnMultipleMatches() {
        KeeperRecord a = record("AAAAAAAAAAAAAAAAAAAAAA", loginData("Dup", "u1", "p1", Collections.emptyList()));
        KeeperRecord b = record("BBBBBBBBBBBBBBBBBBBBBB", loginData("Dup", "u2", "p2", Collections.emptyList()));
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId("login:Dup");
        assertThrows(RuntimeException.class, () -> KeeperCredentialMapper.selectRecord(
                Arrays.asList(a, b), "login:Dup", id, NOOP));
    }

    @Test
    void warnsOnUnrecognizedPrefixedLabelButStillMaps() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new Text("mid_authykey", null, null, new ArrayList<>(Arrays.asList("v"))));
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertEquals("v", out.get("authykey")); // unrecognized suffix is still mapped
        assertTrue(log.warns.stream().anyMatch(w ->
                w.contains("mid_authykey") && w.contains("did you mean") && w.contains("mid_authkey")));
        // login record: user/pswd come from standard fields, so they are not offered as labels
        assertTrue(log.warns.stream().noneMatch(w -> w.contains("mid_user")));
    }

    @Test
    void warnsOnFormStyleMislabeledFieldAndListsValidLabels() {
        // The common mistake: copying the ServiceNow form/column name (private_key) into the label
        // instead of the IExternalCredential value name (VAL_PRIVKEY = "privkey"). Too far from any known
        // name for a "did you mean" typo, but still flagged; the valid names are listed once, prefix-less.
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new Text("mid_private_key", null, null, new ArrayList<>(Arrays.asList("v"))));
        KeeperRecord rec = record(UID, genericData("file", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertEquals("v", out.get("private_key")); // still passed through
        assertTrue(log.warns.stream().anyMatch(w -> w.contains("'mid_private_key'") && w.contains("not a recognized")));
        assertTrue(log.warns.stream().noneMatch(w -> w.contains("did you mean"))); // too far for a suggestion
        // the value-names line prints once, bare (names carry no mid_ prefix), listing privkey and pkey
        assertEquals(1, log.warns.stream().filter(w -> w.contains("prefix each with")).count());
        assertTrue(log.warns.stream().anyMatch(w -> w.contains("privkey") && w.contains("pkey")));
        assertTrue(log.warns.stream().noneMatch(w -> w.contains("mid_privkey"))); // names are not prefixed
    }

    @Test
    void warnsOnUnprefixedKnownFieldWithRenameHint() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new Text("authkey", null, null, new ArrayList<>(Arrays.asList("v"))));
        KeeperRecord rec = record(UID, genericData("file", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertFalse(out.containsKey("authkey")); // unprefixed -> not mapped
        assertTrue(log.warns.stream().anyMatch(w ->
                w.contains("'authkey'") && w.contains("missing") && w.contains("mid_authkey")));
    }

    @Test
    void warnsUnprefixedUserOnLoginPointsToStandardFields() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new Text("user", null, null, new ArrayList<>(Arrays.asList("bob"))));
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertEquals("alice", out.get("user")); // standard Login field wins
        assertTrue(log.warns.stream().anyMatch(w ->
                w.contains("standard Login") && !w.contains("Rename")));
    }

    @Test
    void doesNotWarnOnUnrelatedUnprefixedField() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new Text("client_secret", null, null, new ArrayList<>(Arrays.asList("x"))));
        KeeperRecord rec = record(UID, loginData("MyLogin", "alice", "s3cret", custom));
        CapturingLog log = new CapturingLog();

        KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertTrue(log.warns.isEmpty()); // client_secret is not a known value name -> silent
    }

    @Test
    void validPrefixedFieldMapsWithoutWarning() {
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new HiddenField("mid_authkey", null, null, new ArrayList<>(Arrays.asList("KEY"))));
        KeeperRecord rec = record(UID, genericData("file", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertEquals("KEY", out.get("authkey"));
        assertTrue(log.warns.isEmpty());
        assertTrue(log.errors.isEmpty());
    }

    @Test
    void usesSuppliedValueNamesOverStaticDefault() {
        // CredentialResolver resolves the value-name set at runtime and passes it in; the mapper must
        // validate against that set, not only the static default.
        Set<String> custom = new LinkedHashSet<>(Arrays.asList("user", "pswd", "widget"));
        List<KeeperRecordField> fields = new ArrayList<>();
        fields.add(new Text("mid_widget", null, null, new ArrayList<>(Arrays.asList("w"))));   // valid per custom set
        fields.add(new Text("mid_authkey", null, null, new ArrayList<>(Arrays.asList("a"))));  // NOT in custom set
        KeeperRecord rec = record(UID, genericData("file", fields));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", custom, log);

        assertEquals("w", out.get("widget"));
        assertEquals("a", out.get("authkey")); // still passed through even though flagged
        assertTrue(log.warns.stream().noneMatch(w -> w.contains("'mid_widget'")));  // widget is valid here
        assertTrue(log.warns.stream().anyMatch(w -> w.contains("'mid_authkey'"))); // authkey not in the custom set
    }

    @Test
    void printsAvailableValueNamesOnlyOnce() {
        // 2 valid + 1 invalid label: all are mapped, and the valid-names list is logged exactly once.
        List<KeeperRecordField> custom = new ArrayList<>();
        custom.add(new HiddenField("mid_pkey", null, null, new ArrayList<>(Arrays.asList("k1"))));
        custom.add(new HiddenField("mid_authkey", null, null, new ArrayList<>(Arrays.asList("k2"))));
        custom.add(new Text("mid_zzz", null, null, new ArrayList<>(Arrays.asList("z"))));
        KeeperRecord rec = record(UID, genericData("file", custom));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertEquals("k1", out.get("pkey"));
        assertEquals("k2", out.get("authkey"));
        assertEquals("z", out.get("zzz")); // invalid label still passed through
        assertEquals(1, log.warns.stream().filter(w -> w.contains("prefix each with")).count()); // printed once
        assertTrue(log.warns.stream().anyMatch(w -> w.contains("'mid_zzz'"))); // the invalid one is flagged
        assertTrue(log.warns.stream().noneMatch(w -> w.contains("'mid_pkey'") || w.contains("'mid_authkey'")));
    }

    @Test
    void zeroResolvedLogsAvailableNamesAndReturnsEmpty() {
        // A record with no mappable mid_ fields resolves to nothing: no throw, empty map, and the value
        // names are logged once with a "no values resolved" note.
        KeeperRecord rec = record(UID, genericData("file", Collections.emptyList()));
        CapturingLog log = new CapturingLog();

        Map<String, String> out = KeeperCredentialMapper.mapRecordToCredential(rec, "mid_", log);

        assertTrue(out.isEmpty());
        assertEquals(1, log.warns.stream().filter(w -> w.contains("prefix each with")).count());
        assertTrue(log.warns.stream().anyMatch(w ->
                w.contains("No credential values were resolved") && w.contains("secret_key")));
    }
}
