package com.snc.discovery;

import com.keepersecurity.secretsManager.core.*;
import com.service_now.mid.services.FileSystem;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.net.HttpURLConnection.HTTP_NO_CONTENT;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.file.StandardCopyOption.*;

/**
 * Basic implementation of a CredentialResolver that uses KSM SDK to connect to Keeper vault.
 */
public class CredentialResolver implements IExternalCredential {
    // Required parameters that must be in the config file in order to use KSM.
    // Parameters used to access the vault / credentials
    // KSM Config as base64 string
    public static final String KSM_CONFIG = "ext.cred.keeper.ksm_config";
    private static final String KSM_LABEL_PREFIX = "ext.cred.keeper.ksm_label_prefix";
    private static final String DEF_KSM_LABEL_PREFIX = "mid_";
    private static final String KSM_CACHE = "ext.cred.keeper.use_ksm_cache";
    private static final boolean DEF_KSM_CACHE = false;
    private static final long KSM_CACHE_LIFESPAN = 5*60; // in seconds

    // credId is either record UID (without ':') or type:title
    private static final String DEF_CREDID_SPLIT = ":";

    //Load below parameters from MID config parameters.
    private String ksmConfig = ""; // The KSM config to use as specified in the MID config.xml file
    private String ksmLabelPrefix = ""; // The KSM label prefix to use as specified in the MID config.xml file
    private boolean ksmCache = false; // The KSM cache flag to use as specified in the MID config.xml file

    // Logger object to log messages in agent.log
    private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);

    public CredentialResolver() {}

    /**
     * Return the API version supported by this class.
     * Note: should be less than 1.1 for external credential resolver.
     */
    @Override
    public String getVersion() {
        return "0.1";
    }

    /**
     * Config method with preloaded config parameters from config.xml.
     * @param configMap - contains config parameters with prefix "ext.cred" only.
     */
    @Override
    public void config(Map<String, String> configMap) {
        //Note: To load config parameters from MID config.xml if not available in configMap.
        //propValue = Config.get().getProperty("<Parameter Name>")

        ksmConfig = configMap.get(KSM_CONFIG);
        if(isNullOrEmpty(ksmConfig))
            fLogger.error("[Vault] ERROR - CredentialResolver ksmConfig not set!");
        String configMask = new String(new char[ksmConfig.length()]).replace('\0', '*');
        fLogger.info("ksmConfig: " + configMask);

        ksmLabelPrefix = configMap.get(KSM_LABEL_PREFIX);
        if(isNullOrEmpty(ksmLabelPrefix))
            ksmLabelPrefix = DEF_KSM_LABEL_PREFIX;

        ksmCache = DEF_KSM_CACHE;
        String ksmCacheString = configMap.get(KSM_CACHE);
        if(!isNullOrEmpty(ksmCacheString) && ksmCacheString.equalsIgnoreCase("true"))
            ksmCache = true;
    }

    /*
    // All these are defined in snc-automation-api IExternalCredential:
    // These are the only permissible names of arguments passed INTO the resolve() method.
    public static final String ARG_ID = "id"; // credential identifier as configured on the ServiceNow instance
    public static final String ARG_IP = "ip"; // IPv4 address of the target system (ex. "10.22.231.12")
    public static final String ARG_TYPE = "type"; // type of credential (ssh, snmp, etc.)
    public static final String ARG_MID = "mid"; // the MID server making the request

    // Most common permissible names of values returned FROM the resolve() method.
    public static final String VAL_USER = "user";
    public static final String VAL_PSWD = "pswd";
    public static final String VAL_PASSPHRASE = "passphrase";
    public static final String VAL_PKEY = "pkey";
    public static final String VAL_AUTHPROTO = "authprotocol";
    public static final String VAL_AUTHKEY = "authkey";
    public static final String VAL_PRIVPROTO = "privprotocol";
    public static final String VAL_PRIVKEY = "privkey";
    // for more detailed list check IExternalCredential
    // ex. email, secret_key, client_id, tenant_id
    // for a full list check discovery_credential table on the ServiceNow instance
    // ex. sn_cfg_ansible, sn_disco_certmgmt_certificate_ca, cfg_chef_credentials, etc.
    // The credential map returned from the resolve method is expected
    // to have keys matching with the column names in discovery_credential table.
    */

    /**
     * Resolve a credential.
     */
    @Override
    public Map<String, String> resolve(Map<String, String> args) {
        // the resolved credential is returned in a HashMap...
        Map<String, String> result = new HashMap<>();

        // input params
        String credId = args.get(ARG_ID);
        String credType = args.get(ARG_TYPE);
        String midServer = args.get(ARG_MID);

        if(isNullOrEmpty(credId) || isNullOrEmpty(credType))
            throw new RuntimeException("Empty credential Id or type found.");

        fLogger.info("Resolve - credType: " + credType + ", credId: " + credId + " on midServer: " + midServer);

        // credId is either record UID (without ':') or type:title or :title
        String recType = "";
        String recTitle = "";
        // get record type and title from credId if exists.
        String[] parts = credId.split(Pattern.quote(DEF_CREDID_SPLIT), 2);
        if (parts.length == 1) {
            credId = parts[0].trim();
            if (!credId.matches("^[A-Za-z0-9_-]{22}$")) {
                throw new RuntimeException( "Invalid Credential ID: Record UID must be 22 characters, URL Safe Base64 encoded string");
            }
        } else if (parts.length == 2) {
            // empty record type == search by title (any type) - ex. ':MyUniqueRecordTitle'
            recType = parts[0].trim();
            // empty title is OK - find a single shared record of the given type - ex. 'login:'
            recTitle = parts[1]; // leading/trailing spaces matter
            // ':' is invalid, for records with empty title must provide the record type
            if(isNullOrEmpty(recType) && isNullOrEmpty(recTitle))
                throw new RuntimeException( "Invalid Credential ID: Credential Id must provide record type or title or both as a single string - type:title");
        } else {
            throw new RuntimeException( "Invalid Credential ID: Credential Id has split string more than twice");
        }

        List<String> recordsFilter = Collections.emptyList();
        if(!isNullOrEmpty(recType) || !isNullOrEmpty(recTitle)) {
            fLogger.info(String.format("Record Type: '%s', Record Title: '%s'", recType, recTitle));
        } else {
            fLogger.info(String.format("Record UID: '%s'", credId));
            recordsFilter = Collections.singletonList(credId);
        }

        // Initialize storage
        InMemoryStorage storage;
        try {
            storage = new InMemoryStorage(ksmConfig);
        } catch (Exception e) {
            fLogger.error("### Error loading KSM Config. Make sure " + KSM_CONFIG +
                    " contains valid base64 encoded JSON config.", e.getMessage());
            throw e;
        }

        try {
            // Connect to vault and retrieve credential
            List<KeeperRecord> records = Collections.emptyList();
            KeeperSecrets secrets;
            if (ksmCache)
                secrets = getSecretsCached(storage, recordsFilter);
            else
                secrets = getSecretsThrottled(storage, recordsFilter);

            if (secrets != null)
                records = secrets.getRecords();

            if (records.isEmpty()) {
                fLogger.error("### Unable to find any records matching Credential ID: " + credId);
                throw new RuntimeException("No records match Credential ID: " + credId);
            } else if (records.size() > 1 && !recordsFilter.isEmpty()) {
                fLogger.error("### Multiple records match Credential ID: " + credId);
                throw new RuntimeException("Multiple records match Credential ID");
            }

            // find matching record
            KeeperRecord record = null;
            if (recordsFilter.isEmpty()) {
                // no filter - search by type:title
                List<KeeperRecord> found = new ArrayList<>();
                for (KeeperRecord rec : records) {
                    boolean matchesType = isNullOrEmpty(recType) || recType.equals(rec.getType());
                    boolean matchesTitle = recTitle.isEmpty() || recTitle.equals(rec.getTitle());
                    if (matchesType && matchesTitle) {
                        found.add(rec);
                    }
                }
                if (found.size() == 1)
                    record = found.get(0);
                else if (found.isEmpty()) {
                    fLogger.error("### Unable to find any records matching Credential ID: " + credId);
                    throw new RuntimeException("No records match Credential ID: " + credId);
                } else {
                    List<String> ids = found.stream().map(KeeperRecord::getRecordUid).collect(Collectors.toList());
                    fLogger.error("### Multiple records match Credential ID: " + credId + " - " + String.join(",", ids));
                    throw new RuntimeException("Multiple records match Credential ID");
                }
            } else {
                record = records.get(0);
            }

            // Grab the field values from the returned object
            // NB! Always gets all fields with labels matching the prefix
            // NB! Login records - always gets user/pass from corresponding fields ignoring any labels
            if (record != null) {
                // for Login records user/pass always come from corresponding record fields
                if ("login".equalsIgnoreCase(record.getType())) {
                    String password = record.getPassword();
                    if (!isNullOrEmpty(password))
                        result.put(VAL_PSWD, password);
                    KeeperRecordField loginField = record.getData().getField(Login.class);
                    if (loginField != null) {
                        List<String> value = ((Login)loginField).getValue();
                        if (!value.isEmpty())
                            if (!isNullOrEmpty(value.get(0)))
                                result.put(VAL_USER, value.get(0));
                    }
                }

                // find fields by label prefix
                List<KeeperRecordField> fields = record.getData().getCustom();
                fields = (fields != null ? fields : new ArrayList<>());
                for (KeeperRecordField field : fields) {
                    String label = field.getLabel();
                    if (!isNullOrEmpty(label) && label.startsWith(ksmLabelPrefix)){
                        String key = label.substring(ksmLabelPrefix.length());
                        if (isNullOrEmpty(key)) {
                            fLogger.warn("### Skipped empty key for field: " + label);
                        } else if (result.containsKey(key)) {
                            fLogger.warn("### Skipped duplicate entry for field: " + label);
                        } else {
                            List<String> values = Collections.emptyList();
                            if (field instanceof Text){
                                Text fld = (Text)field;
                                values = fld.getValue();
                            } else if (field instanceof HiddenField) {
                                HiddenField fld = (HiddenField)field;
                                values = fld.getValue();
                            } else if (field instanceof Multiline) {
                                Multiline fld = (Multiline)field;
                                values = fld.getValue();
                            } else {
                                fLogger.error("### Skipped unexpected field type for field: " + label + " Only fields of type Text, Multiline or HiddenField are allowed.");
                            }
                            if (values.isEmpty())
                                fLogger.warn("### Skipped empty field value for field: " + label);
                            else {
                                String val = values.get(0);
                                if (isNullOrEmpty(val))
                                    fLogger.warn("### Skipped empty field value for field: " + label);
                                else
                                    result.put(key, val);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            fLogger.error("### Unable to find credential from KSM App.", e);
        }

        if (!result.containsKey(VAL_USER))
            fLogger.warn("### No value for username in credential: " + credId);
        if (!result.containsKey(VAL_PSWD))
            fLogger.warn("### No value for password in credential: " + credId);
        fLogger.info("### Credential: " + credId + " Resolved keys: " + result.keySet() + " UseCache: " + ksmCache);

        return result;
    }

    private static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    private KeeperSecrets getSecretsThrottled(InMemoryStorage storage, List<String> recordsFilter) throws Exception {
        KeeperSecrets secrets = null;
        SecretsManagerOptions options = new SecretsManagerOptions(storage);
        // MID Server [Test credential] seems to timeout after 90 sec
        // yet mid server resolves (as seen in logs - even 120s later)
        int numRetries = 8; // keep it below 90 sec
        while (--numRetries >= 0) {
            try {
                long secs = System.currentTimeMillis() / 1000;
                long delay = 10 - (secs % 10); // seconds to next throttle bucket
                if (delay < 10) Thread.sleep(delay * 1000);
                secrets = SecretsManager.getSecrets(options, recordsFilter);
                numRetries = -1;
            } catch (Exception e) {
                fLogger.error("e.Message: " + e.getMessage());
                if (numRetries <= 0 || !e.getMessage().contains("\"error\":\"throttled\""))
                    throw e;
                else
                    fLogger.error("### KSM App throttled... retries left: " + numRetries);
            }
        }
        return secrets;
    }

    private KeeperSecrets getSecretsCached(InMemoryStorage storage, List<String> recordsFilter) throws Exception {
        KeeperSecrets secrets = getCachedData(storage); // always cache all records

        // filter only requested records
        if (!recordsFilter.isEmpty()) {
            List<KeeperRecord> records = secrets.getRecords();
            List<KeeperRecord> filtered = records.stream().filter(
                    record -> recordsFilter.contains(record.getRecordUid())).collect(Collectors.toList());
            records.clear();
            records.addAll(filtered);
        }

        return secrets;
    }

    private KeeperSecrets getCachedData(InMemoryStorage storage) throws Exception {
        String cacheFilename = getCacheFilename();
        String tempFilename = getCacheTmpFilename();

        // while there are pending reader locks (exclusive) writer can't get through
        // but will try writer lock on the new temp file
        boolean needsUpdate = !isFileRecent(KSM_CACHE_LIFESPAN, cacheFilename);
        if (needsUpdate) {
            // see getSecretsThrottled for timeouts info
            int numRetries = 8; // 8*10=80 sec delay - keep < 90 sec
            for (int i = 0; i < numRetries; i++) {
                try {
                    // getCachedData - saveCachedValue write lock conflict (not an issue on Linux though):
                    // reacquiring write lock fails on some platforms (Win) - make sure locked regions don't overlap
                    try (RandomAccessFile writer = new RandomAccessFile(tempFilename, "rw");
                         FileChannel channel = writer.getChannel();
                         FileLock fileLock = channel.tryLock(Long.MAX_VALUE-1, 1, false)){
                        // lock a region way beyond cached data size to allow saveCachedValue to fit in front
                        if (fileLock != null) {
                            // recheck if cache updated while waiting for the lock
                            if (isFileRecent(KSM_CACHE_LIFESPAN, cacheFilename))
                                break;
                            SecretsManagerOptions options = new SecretsManagerOptions(storage, (url, key, payload)-> {
                                try {
                                    return cachingPostFunction(url, key, payload);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                            });
                            return SecretsManager.getSecrets(options);
                        }
                    } finally {
                        // due to the write lock contention saveCachedValue can't move/delete tmp file on its own
                        try { Files.delete(Paths.get(tempFilename)); } catch(Exception e) { fLogger.error("### Failed to delete temp cache file."); }
                    }
                } catch (Exception e) {
                    fLogger.error("### KSM Exception: ", e);
                }
                if (i < 7) // keep total delay < 90 sec
                    Thread.sleep(10_000);
            }
        }
        // read from cache - note: if update was needed but failed cached data may be stale
        SecretsManagerOptions options = new SecretsManagerOptions(storage, (url, key, payload)-> {
            try {
                return cachedPostFunction(url, key, payload);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        return SecretsManager.getSecrets(options);
    }

    private boolean isFileRecent(long lifespanSeconds, String filename) throws Exception {
        boolean isRecent = false;
        File file = new File(filename);
        if (file.exists()) {
            BasicFileAttributes attr = Files.readAttributes(Paths.get(filename), BasicFileAttributes.class);
            long curTimestamp = System.currentTimeMillis() / 1000;
            long diffC = Math.abs(curTimestamp - (attr.creationTime().toMillis() / 1000));
            long diffLM = Math.abs(curTimestamp - (attr.lastModifiedTime().toMillis() / 1000));
            isRecent = attr.size() >= 32 && (diffC <= lifespanSeconds || diffLM <= lifespanSeconds);
        }
        return isRecent;
    }

    private KeeperHttpResponse cachingPostFunction(String url, TransmissionKey transmissionKey, EncryptedPayload payload) throws Exception {
        KeeperHttpResponse response = SecretsManager.postFunction(url, transmissionKey, payload, false);
        if (response.getStatusCode() == HTTP_OK) {
            saveCachedValue(transmissionKey.getKey(), response.getData());
        }
        return response;
    }

    private KeeperHttpResponse cachedPostFunction(String url, TransmissionKey transmissionKey, EncryptedPayload payload) throws Exception {
        String cacheFilename = getCacheFilename();
        for (int i = 0; i < 5; i++) {
            try (FileInputStream reader = new FileInputStream(cacheFilename);
                 FileChannel channel = reader.getChannel();
                 FileLock fileLock = channel.tryLock(0L, Long.MAX_VALUE, true)) {
                if (fileLock != null) {
                    byte[] cachedData = getCachedValue();
                    transmissionKey.setKey(Arrays.copyOfRange(cachedData, 0, 32));
                    byte [] data = Arrays.copyOfRange(cachedData, 32, cachedData.length);
                    return new KeeperHttpResponse(HTTP_OK, data);
                }
            }
            Thread.sleep(100);
        }
        return new KeeperHttpResponse(HTTP_NO_CONTENT, new byte[]{});
    }

    private static void saveCachedValue(byte[] key, byte[] data) throws Exception {
        Path tmpPath = Paths.get(getCacheTmpFilename()); // ksm_cache.tmp
        Path tmpPath_ = Paths.get(getCacheTmpFilename()+"_");  // ksm_cache.tmp_
        Path dstPath = Paths.get(getCacheFilename()); // ksm_cache.dat
        // note: reacquiring write lock fails on some platforms (Win) - make sure locked regions don't overlap
        try (RandomAccessFile out = new RandomAccessFile(tmpPath.toString(), "rw");
             FileLock lock = out.getChannel().lock(0, key.length + data.length, false)){
            out.seek(0);
            out.write(key);
            out.write(data);
            // not all OS update lastModified on create
            Files.setLastModifiedTime(tmpPath, FileTime.fromMillis(System.currentTimeMillis()));
        }

        // On some platforms (Windows) file move fails if caller locked tmpPath (which works on Linux)
        // hence the need to copy from locked file to a new one to use ATOMIC_MOVE
        Files.copy(tmpPath, tmpPath_, REPLACE_EXISTING, COPY_ATTRIBUTES); // replace and copy last-modified-time

        // Moving a file will copy the last-modified-time to the target file
        try {
            // not all platforms support atomic move
            Files.move(tmpPath_, dstPath, REPLACE_EXISTING, ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ame) {
            Files.move(tmpPath_, dstPath, REPLACE_EXISTING);
        }
        // tmpPath is still locked and will be deleted by the caller after getSecrets completes
    }

    private static byte[] getCachedValue() throws Exception {
        try (InputStream ins = Files.newInputStream(Paths.get(getCacheFilename()));
             DataInputStream dis = new DataInputStream(ins)
        ) {
            //ins.reset();
            byte[] bytes = new byte[ins.available()];
            dis.readFully(bytes);
            return bytes;
        }
    }


    public static String getCacheDir() {
        //return FileSystem.get().getHomePath(); // home vs work path
        return FileSystem.get().getWorkDir().getAbsolutePath();
    }

    public static String getCacheFilename() {
        return Paths.get(getCacheDir(), "ksm_cache.dat").toString();
    }

    public static String getCacheTmpFilename() {
        return Paths.get(getCacheDir(), "ksm_cache.tmp").toString();
    }

    //main method to test locally, provide KSM config and test it
    // TODO: Remove this before moving to production
    /*
    // Note Java16+ needs following setup (Vancouver+ switched from Java11 to Java17)
    // export _JAVA_OPTIONS="--add-opens=java.base/sun.security.util=ALL-UNNAMED"
    public static void main(String[] args) {
        CredentialResolver credResolver = new CredentialResolver();
        credResolver.ksmConfig = "[Base64_KSM_Config]";
        credResolver.ksmLabelPrefix = "mid_";
        credResolver.ksmCache = false;

        Map<String, String> map = new HashMap<>();
        map.put(ARG_ID, "[RecordUid]");
        map.put(ARG_TYPE, "ssh_password");

        Map<String, String> result = credResolver.resolve(map);
        fLogger.info(result.toString());
    }
    */
}
