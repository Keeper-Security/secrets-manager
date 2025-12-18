package org.example;

import com.keepersecurity.secretsManager.core.*;
import static com.keepersecurity.secretsManager.core.SecretsManager.*;
import static com.keepersecurity.secretsManager.core.Notation.*;
import static com.keepersecurity.secretsManager.core.LocalConfigStorageKt.*;

import java.io.FileOutputStream;
import java.security.Security;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.nio.ByteBuffer;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

// This is basic example of creating custom caching function
// ⓘ saveCachedValue and getCachedValue only store last request, however you can use any tool to extend this functionality
// ⓘ Stale cache entries can cause version mismatches if records are updated from other keepersecurity utils. Prefer fresh reads

public class App {

    private static KeeperHttpResponse cachingPostFunction(String url, TransmissionKey transmissionKey, EncryptedPayload payload) {
        try {
            KeeperHttpResponse response = postFunction(url, transmissionKey, payload, false);
            if (response.getStatusCode() == HttpURLConnection.HTTP_OK) {
                byte[] transmissionKeyValue = transmissionKey.getKey();
                byte[] data = response.getData();
                saveCachedValue(ByteBuffer.allocate(transmissionKeyValue.length + data.length).put(transmissionKeyValue).put(data).array());
            }
            return response;
        } catch (Exception e) {
            byte[] cachedData = getCachedValue();
            byte[] cachedTransmissionKey = Arrays.copyOfRange(cachedData, 0, 32);
            transmissionKey.setKey(cachedTransmissionKey);
            byte[] data = Arrays.copyOfRange(cachedData, 32, cachedData.length);
            return new KeeperHttpResponse(HttpURLConnection.HTTP_OK, data);
        }
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"");
            System.out.println("F.e. ./gradlew run --args=\"config.json US:EXAMPLE_ONE_TIME_TOKEN\"");
            System.out.println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%");
            return;
        }

        Security.addProvider(new BouncyCastleFipsProvider());

        KeyValueStorage storage = new LocalConfigStorage(args[0]);
        System.out.printf("Local Config Storage opened from the file '%s'%n", args[0]);
        try {
            if (args.length > 1) {
                System.out.printf("Local Config Storage initialized with the Client Key '%s'%n", args[1]);
                // if your Keeper Account is in other region than US, update the hostname accordingly
                initializeStorage(storage, args[1], "keepersecurity.com");
            }
            // SecretsManagerOptions options = new SecretsManagerOptions(storage);
            SecretsManagerOptions options = new SecretsManagerOptions(storage, App::cachingPostFunction);
            KeeperSecrets secrets = getSecrets(options);
            System.out.println(secrets.getRecords());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
