package com.keepersecurity.secretsManager;

import com.keepersecurity.secretsManager.core.HiddenField;
import com.keepersecurity.secretsManager.core.KeeperRecord;
import com.keepersecurity.secretsManager.core.KeeperRecordField;
import com.keepersecurity.secretsManager.core.Login;
import com.keepersecurity.secretsManager.core.Multiline;
import com.keepersecurity.secretsManager.core.Text;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Pure credential-resolution logic shared by the resolver classes.
 *
 * This class deliberately depends only on the Keeper Secrets Manager SDK (no MID Server
 * classes), so it can be unit tested without a MID Server on the classpath. Diagnostics are
 * emitted through the {@link Log} sink supplied by the caller so that, at runtime, messages
 * still reach the MID Server's agent.log.
 */
public final class KeeperCredentialMapper {

    // Values must match IExternalCredential.VAL_USER / VAL_PSWD (kept as literals to stay MID-free).
    static final String VAL_USER = "user";
    static final String VAL_PSWD = "pswd";

    // credId is either a record UID (without ':') or type:title
    private static final String DEF_CREDID_SPLIT = ":";

    private KeeperCredentialMapper() {
    }

    /** Minimal logging sink so this MID-free class can still report through the MID logger. */
    public interface Log {
        void warn(String message);
        void error(String message);
    }

    /** Parsed Credential ID: either a record UID lookup, or a type/title search. */
    public static final class CredId {
        /** Non-null (validated 22-char UID) for a UID lookup; null for a type:title search. */
        public final String recordUid;
        /** Empty string when not provided. */
        public final String recType;
        /** Empty string when not provided; leading/trailing spaces are significant for matching. */
        public final String recTitle;

        CredId(String recordUid, String recType, String recTitle) {
            this.recordUid = recordUid;
            this.recType = recType;
            this.recTitle = recTitle;
        }

        public boolean isUidLookup() {
            return recordUid != null;
        }
    }

    /**
     * Parse a Credential ID into either a record UID or a type:title search.
     * Accepts a 22-char URL-safe base64 UID, or "type:title" / ":title" / "type:".
     */
    public static CredId parseCredId(String credId) {
        // get record type and title from credId if exists.
        String[] parts = credId.split(Pattern.quote(DEF_CREDID_SPLIT), 2);
        if (parts.length == 1) {
            String uid = parts[0].trim();
            if (!uid.matches("^[A-Za-z0-9_-]{22}$")) {
                throw new RuntimeException("Invalid Credential ID: Record UID must be 22 characters, URL Safe Base64 encoded string");
            }
            return new CredId(uid, "", "");
        }
        // parts.length == 2 (split limit 2 yields at most two elements)
        // empty record type == search by title (any type) - ex. ':MyUniqueRecordTitle'
        String recType = parts[0].trim();
        // empty title is OK - find a single shared record of the given type - ex. 'login:'
        String recTitle = parts[1]; // leading/trailing spaces matter
        // ':' is invalid, for records with empty title must provide the record type
        if (isNullOrEmpty(recType) && isNullOrEmpty(recTitle)) {
            throw new RuntimeException("Invalid Credential ID: Credential Id must provide record type or title or both as a single string - type:title");
        }
        return new CredId(null, recType, recTitle);
    }

    /**
     * Select the single record matching the Credential ID. For a UID lookup the record set was
     * already server-side filtered; for a type:title search the (possibly full) record set is
     * matched in memory - unrelated records (e.g. PAM records shared to the app) are ignored.
     * Throws when zero or more than one record matches.
     */
    public static KeeperRecord selectRecord(List<KeeperRecord> records, String credId, CredId id, Log log) {
        if (records.isEmpty()) {
            log.error("### Unable to find any records matching Credential ID: " + credId);
            throw new RuntimeException("No records match Credential ID: " + credId);
        } else if (records.size() > 1 && id.isUidLookup()) {
            log.error("### Multiple records match Credential ID: " + credId);
            throw new RuntimeException("Multiple records match Credential ID");
        }

        if (id.isUidLookup()) {
            return records.get(0);
        }

        // no filter - search by type:title
        List<KeeperRecord> found = new ArrayList<>();
        for (KeeperRecord rec : records) {
            boolean matchesType = isNullOrEmpty(id.recType) || id.recType.equals(rec.getType());
            boolean matchesTitle = id.recTitle.isEmpty() || id.recTitle.equals(rec.getTitle());
            if (matchesType && matchesTitle) {
                found.add(rec);
            }
        }
        if (found.size() == 1) {
            return found.get(0);
        } else if (found.isEmpty()) {
            log.error("### Unable to find any records matching Credential ID: " + credId);
            throw new RuntimeException("No records match Credential ID: " + credId);
        } else {
            List<String> ids = found.stream().map(KeeperRecord::getRecordUid).collect(Collectors.toList());
            log.error("### Multiple records match Credential ID: " + credId + " - " + String.join(",", ids));
            throw new RuntimeException("Multiple records match Credential ID");
        }
    }

    /**
     * Extract credential values from a record.
     * NB! Always gets all custom fields with labels matching the prefix.
     * NB! Login records - always get user/pass from the corresponding standard fields ignoring any labels.
     */
    public static Map<String, String> mapRecordToCredential(KeeperRecord record, String labelPrefix, Log log) {
        Map<String, String> result = new HashMap<>();
        if (record == null) {
            return result;
        }

        // for Login records user/pass always come from corresponding record fields
        if ("login".equalsIgnoreCase(record.getType())) {
            String password = record.getPassword();
            if (!isNullOrEmpty(password)) {
                result.put(VAL_PSWD, password);
            }
            KeeperRecordField loginField = record.getData().getField(Login.class);
            if (loginField != null) {
                List<String> value = ((Login) loginField).getValue();
                if (!value.isEmpty() && !isNullOrEmpty(value.get(0))) {
                    result.put(VAL_USER, value.get(0));
                }
            }
        }

        // find fields by label prefix
        List<KeeperRecordField> fields = record.getData().getCustom();
        fields = (fields != null ? fields : new ArrayList<KeeperRecordField>());
        for (KeeperRecordField field : fields) {
            String label = field.getLabel();
            if (isNullOrEmpty(label) || !label.startsWith(labelPrefix)) {
                continue;
            }
            String key = label.substring(labelPrefix.length());
            if (isNullOrEmpty(key)) {
                log.warn("### Skipped empty key for field: " + label);
                continue;
            }
            if (result.containsKey(key)) {
                log.warn("### Skipped duplicate entry for field: " + label);
                continue;
            }
            List<String> values = Collections.emptyList();
            if (field instanceof Text) {
                values = ((Text) field).getValue();
            } else if (field instanceof HiddenField) {
                values = ((HiddenField) field).getValue();
            } else if (field instanceof Multiline) {
                values = ((Multiline) field).getValue();
            } else {
                log.error("### Skipped unexpected field type for field: " + label + " Only fields of type Text, Multiline or HiddenField are allowed.");
            }
            if (values.isEmpty()) {
                log.warn("### Skipped empty field value for field: " + label);
                continue;
            }
            String val = values.get(0);
            if (isNullOrEmpty(val)) {
                log.warn("### Skipped empty field value for field: " + label);
            } else {
                result.put(key, val);
            }
        }
        return result;
    }

    private static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }
}
