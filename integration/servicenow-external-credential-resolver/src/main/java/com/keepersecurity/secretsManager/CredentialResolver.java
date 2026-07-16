package com.keepersecurity.secretsManager;

import com.keepersecurity.secretsManager.core.*;
import com.service_now.mid.services.FileSystem;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.stream.Collectors;

import static java.net.HttpURLConnection.HTTP_NO_CONTENT;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.file.StandardCopyOption.*;

/**
 * Keeper Secrets Manager external credential resolver.
 *
 * <p>This is the canonical implementation. On ServiceNow Yokohama (Patch 7+) and newer, register
 * the resolver by its fully qualified class name {@code com.keepersecurity.secretsManager.CredentialResolver};
 * using a Keeper-owned class name lets it coexist with other vendors' resolvers (CyberArk,
 * HashiCorp, Delinea, …) on the same MID Server. Xanadu and older MID Servers require the shared
 * class name {@code com.snc.discovery.CredentialResolver} (a thin subclass of this class), which
 * ships only in the ("legacy") JAR variant.</p>
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

    //Load below parameters from MID config parameters.
    private String ksmConfig = ""; // The KSM config to use as specified in the MID config.xml file
    private String ksmLabelPrefix = ""; // The KSM label prefix to use as specified in the MID config.xml file
    private boolean ksmCache = false; // The KSM cache flag to use as specified in the MID config.xml file

    // Logger object to log messages in agent.log
    private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);

    // Value names ServiceNow recognizes, resolved once at load time from the IExternalCredential interface
    // so the resolver tracks any VAL_* values ServiceNow adds without a code change. Passed into the mapper,
    // which falls back to its own static list when this is empty. Resolution is fully guarded: a failure
    // here must never prevent the (rock-solid) resolver from loading or resolving credentials.
    private static final Set<String> KNOWN_VALUE_NAMES = resolveKnownValueNames();

    private static Set<String> resolveKnownValueNames() {
        Set<String> names = new LinkedHashSet<>();
        try {
            for (Field f : IExternalCredential.class.getFields()) {
                if (f.getName().startsWith("VAL_") && f.getType() == String.class) {
                    Object value = f.get(null);
                    if (value != null) {
                        names.add((String) value);
                    }
                }
            }
        } catch (Throwable t) {
            fLogger.warn("[Vault] Could not resolve VAL_* names from IExternalCredential (" + t.getMessage()
                    + "); the resolver's built-in list will be used.");
        }
        return names;
    }

    // Bridges the MID-free KeeperCredentialMapper diagnostics to the MID Server logger.
    private final KeeperCredentialMapper.Log midLog = new KeeperCredentialMapper.Log() {
        @Override public void warn(String message) { fLogger.warn(message); }
        @Override public void error(String message) { fLogger.error(message); }
    };

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
        if (isNullOrEmpty(ksmConfig)) {
            // Do not fall through to the mask below: ksmConfig is null/empty, so new char[length()]
            // would throw a raw NullPointerException and hide this actionable message. resolve() will
            // then fail cleanly per request when it tries to load the (missing) config.
            fLogger.error("[Vault] ERROR - CredentialResolver ksmConfig (" + KSM_CONFIG + ") not set!");
        } else {
            String configMask = new String(new char[ksmConfig.length()]).replace('\0', '*');
            fLogger.info("ksmConfig: " + configMask);
        }

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
        String credId = (String) args.get(ARG_ID);
        String credType = (String) args.get(ARG_TYPE);
        String midServer = (String) args.get(ARG_MID);

        if(isNullOrEmpty(credId) || isNullOrEmpty(credType))
            throw new RuntimeException("Empty credential Id or type found.");

        fLogger.info("Resolve - credType: " + credType + ", credId: " + credId + " on midServer: " + midServer);

        // credId is either record UID (without ':') or type:title or :title
        KeeperCredentialMapper.CredId id = KeeperCredentialMapper.parseCredId(credId);

        List<String> recordsFilter = Collections.<String>emptyList();
        if (id.isUidLookup()) {
            fLogger.info(String.format("Record UID: '%s'", id.recordUid));
            recordsFilter = Collections.singletonList(id.recordUid);
        } else {
            fLogger.info(String.format("Record Type: '%s', Record Title: '%s'", id.recType, id.recTitle));
        }

        // Initialize storage
        InMemoryStorage storage = null;
        try {
            storage = new InMemoryStorage(ksmConfig);
        } catch (Exception e) {
            fLogger.error("### Error loading KSM Config. Make sure " + KSM_CONFIG +
                    " contains valid base64 encoded JSON config.", e.getMessage());
            throw e;
        }

        try {
            // Connect to vault and retrieve credential
            List<KeeperRecord> records = Collections.<KeeperRecord> emptyList();
            KeeperSecrets secrets;
            if (ksmCache)
                secrets = getSecretsCached(storage, recordsFilter);
            else
                secrets = getSecretsThrottled(storage, recordsFilter);

            if (secrets != null)
                records = secrets.getRecords();

            // find matching record (validates a single match); a full fetch may include unrelated
            // records (e.g. PAM records shared to the app) which are ignored during selection/mapping
            KeeperRecord record = KeeperCredentialMapper.selectRecord(records, credId, id, midLog);

            // Grab the field values from the returned object
            result.putAll(KeeperCredentialMapper.mapRecordToCredential(record, ksmLabelPrefix, KNOWN_VALUE_NAMES, midLog));
        } catch (Exception e) {
            // Log and continue - never rethrow: a lookup/fetch failure must not prevent the resolver from
            // returning whatever it could resolve. The cause is in agent.log for troubleshooting.
            fLogger.error("### Unable to resolve credential '" + credId + "' from Keeper Secrets Manager: "
                    + e.getMessage(), e);
        }
        // Note: the mapper logs the available value names once (and a "no values resolved" note when empty);
        // resolve() never throws on a labeling/lookup problem - it returns whatever it resolved.

        if (!result.containsKey(VAL_USER))
            fLogger.warn("### No value for username in credential: " + credId);
        if (!result.containsKey(VAL_PSWD))
            fLogger.warn("### No value for password in credential: " + credId);
        fLogger.info("### Credential: " + credId + " Resolved " + result.size() + " keys: " + result.keySet() + " UseCache: " + ksmCache);

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
             DataInputStream dis = new DataInputStream(ins);
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
