package com.keepersecurity.secretsManager;

import com.keepersecurity.secretsManager.core.HiddenField;
import com.keepersecurity.secretsManager.core.KeeperRecord;
import com.keepersecurity.secretsManager.core.KeeperRecordField;
import com.keepersecurity.secretsManager.core.Login;
import com.keepersecurity.secretsManager.core.Multiline;
import com.keepersecurity.secretsManager.core.Text;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    // Authoritative supported value names - must match the IExternalCredential VAL_* constants (kept as
    // literals to stay MID-free, same pattern as VAL_USER/VAL_PSWD above). Ordered + immutable so the
    // diagnostic messages below are deterministic.
    static final Set<String> KNOWN_VALUE_NAMES = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            VAL_USER, VAL_PSWD, "passphrase", "pkey", "sshcert",
            "authprotocol", "authkey", "privprotocol", "privkey",
            "secret_key", "client_id", "tenant_id", "email")));

    // Max edit distance for treating an unrecognized prefixed suffix as a likely typo of a known name.
    private static final int MAX_TYPO_DISTANCE = 2;

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
     * NB! Login and PAM User (pamUser) records - always get user/pass from the corresponding standard
     *     Login/Password fields, ignoring any labels.
     */
    public static Map<String, String> mapRecordToCredential(KeeperRecord record, String labelPrefix, Log log) {
        Map<String, String> result = new HashMap<>();
        if (record == null) {
            return result;
        }

        // Login and PAM User (pamUser) records carry username/password as standard Login/Password
        // fields; read them directly (ignoring any custom labels), the same for both types.
        String recordType = record.getType();
        boolean loginOrPamUser = "login".equalsIgnoreCase(recordType) || "pamUser".equalsIgnoreCase(recordType);
        if (loginOrPamUser) {
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
            if (isNullOrEmpty(label)) {
                continue;
            }
            if (!label.startsWith(labelPrefix)) {
                // Unprefixed field: only flag it when its bare label exactly matches a known value name
                // (ex. "authkey" without the prefix). Unrelated custom fields stay silent - no noise.
                if (KNOWN_VALUE_NAMES.contains(label)) {
                    if (loginOrPamUser && (VAL_USER.equals(label) || VAL_PSWD.equals(label))) {
                        log.warn("### Custom field label '" + label + "' is ignored: for " + recordType
                                + " records the username and password come from the record's standard Login and "
                                + "Password fields, not custom labels.");
                    } else {
                        log.warn("### Custom field label '" + label + "' matches ServiceNow value name '" + label
                                + "' but is missing the '" + labelPrefix + "' prefix, so it is ignored. Rename it to '"
                                + labelPrefix + label + "' to map it. "
                                + describeAvailableCredentials(recordType, labelPrefix) + ".");
                    }
                }
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
                // Prefixed but the stripped suffix is not a known value name: still map it (arbitrary
                // discovery_credential columns are intentionally supported), but warn on a likely typo.
                if (!KNOWN_VALUE_NAMES.contains(key)) {
                    String suggestion = closestKnownName(key);
                    if (suggestion != null) {
                        log.warn("### Custom field label '" + label + "' maps to '" + key + "', which is not a "
                                + "recognized ServiceNow value name - did you mean '" + labelPrefix + suggestion
                                + "'? It will still be mapped in case it matches a discovery_credential column. "
                                + describeAvailableCredentials(recordType, labelPrefix) + ".");
                    }
                }
                result.put(key, val);
            }
        }
        return result;
    }

    /**
     * Human-readable list of the credential labels the user can add, used in diagnostics. Record-type
     * aware: for login/pamUser records username/password come from the standard Login/Password fields,
     * so user/pswd are described separately and omitted from the prefixed-label list.
     */
    public static String describeAvailableCredentials(String recordType, String labelPrefix) {
        boolean loginOrPamUser = "login".equalsIgnoreCase(recordType) || "pamUser".equalsIgnoreCase(recordType);
        String prefix = (labelPrefix != null) ? labelPrefix : "";
        List<String> labels = new ArrayList<>();
        for (String name : KNOWN_VALUE_NAMES) {
            if (loginOrPamUser && (VAL_USER.equals(name) || VAL_PSWD.equals(name))) {
                continue;
            }
            labels.add(prefix + name);
        }
        String lead = loginOrPamUser
                ? "For login and pamUser records the username and password come from the record's standard "
                        + "Login and Password fields; the available credential labels are: "
                : "The available credential labels are: ";
        return lead + String.join(", ", labels);
    }

    /** Message for a record that matched the Credential ID but yielded no usable credential values. */
    static String buildNoUsableFieldsMessage(KeeperRecord record, String credId, String labelPrefix) {
        String type = (record != null) ? record.getType() : null;
        String title = (record != null) ? record.getTitle() : null;
        return "Credential '" + credId + "' matched a record (type '" + type + "', title '" + title
                + "') but no usable values were resolved from it. "
                + describeAvailableCredentials(type, labelPrefix) + ".";
    }

    /**
     * Enforce that at least one credential value was resolved. An empty result means the credential is
     * unusable (no matching record data, or nothing correctly labeled); log the actionable message and
     * throw so it surfaces in the ServiceNow "Test credential" result. A non-empty (even partial) map is
     * returned unchanged.
     */
    public static Map<String, String> requireUsable(Map<String, String> result, KeeperRecord record,
                                                     String credId, String labelPrefix, Log log) {
        if (result.isEmpty()) {
            String msg = buildNoUsableFieldsMessage(record, credId, labelPrefix);
            log.error("### " + msg);
            throw new RuntimeException(msg);
        }
        return result;
    }

    /** Nearest known value name within MAX_TYPO_DISTANCE edits of the given key, or null if none. */
    private static String closestKnownName(String key) {
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String name : KNOWN_VALUE_NAMES) {
            int distance = editDistance(key, name);
            if (distance < bestDistance) {
                bestDistance = distance;
                best = name;
            }
        }
        return (bestDistance <= MAX_TYPO_DISTANCE) ? best : null;
    }

    /** Standard iterative Levenshtein edit distance. */
    private static int editDistance(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }
        return prev[b.length()];
    }

    private static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }
}
