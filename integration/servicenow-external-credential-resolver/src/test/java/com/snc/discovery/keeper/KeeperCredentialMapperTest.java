package com.snc.discovery.keeper;

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
import java.util.List;
import java.util.Map;

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

    private static KeeperRecordData loginData(String title, String user, String pass, List<KeeperRecordField> custom) {
        List<KeeperRecordField> fields = new ArrayList<>();
        fields.add(new Login(user));
        fields.add(new Password(pass));
        return new KeeperRecordData(title, "login", fields, new ArrayList<>(custom));
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
}
