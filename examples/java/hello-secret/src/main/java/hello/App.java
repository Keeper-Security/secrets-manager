package hello;

import com.keepersecurity.secretsManager.core.*;
import static com.keepersecurity.secretsManager.core.SecretsManager.*;

import java.io.FileOutputStream;

public class App {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"");
            System.out.println("F.e. ./gradlew run --args=\"config.json EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8\"");
            System.out.println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%");
            return;
        }
        KeyValueStorage storage = new LocalConfigStorage(args[0]);
        System.out.printf("Local Config Storage opened from the file '%s'%n", args[0]);
        try {
            if (args.length > 1) {
                System.out.printf("Local Config Storage initialized with the Client Key '%s'%n", args[1]);
                // if your Keeper Account is in other region than US, update the hostname accordingly
                initializeStorage(storage, args[1], "keepersecurity.com");
            }
            SecretsManagerOptions options = new SecretsManagerOptions(storage);
//            SecretsManagerOptions options = new SecretsManagerOptions(storage, SecretsManager::cachingPostFunction);
            KeeperSecrets secrets = getSecrets(options);
//            KeeperSecrets secrets = getSecrets(options, Arrays.asList("UlzQ-jKQTgQcEvpJI9vxxQ"));
            System.out.println(secrets.getRecords());

            // get the password from the first record
            KeeperRecord firstRecord = secrets.getRecords().get(0);
            String firstRecordPassword = firstRecord.getPassword();
            System.out.println(firstRecordPassword);

            // download the file from the 3rd record
            KeeperFile file = secrets.getRecords().get(2).getFileByName("acme.cer");
            if (file != null) {
                byte[] fileBytes = downloadFile(file);
                try (FileOutputStream fos = new FileOutputStream(file.getData().getName())) {
                    fos.write(fileBytes);
                }
            }

            // update the password on the first record
            firstRecord.updatePassword("aP1$t367QOCvL$eM$bG#");
            updateSecret(options, firstRecord);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
