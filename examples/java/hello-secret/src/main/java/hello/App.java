package hello;

import com.keepersecurity.secretsManager.core.*;
import static com.keepersecurity.secretsManager.core.SecretsManager.*;

import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.List;

public class App {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"");
            System.out.println("F.e. ./gradlew run --args=\"config.txt EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8\"");
            System.out.println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%");
            return;
        }
        KeyValueStorage storage = new LocalConfigStorage(args[0]);
        System.out.printf("Local Config Storage opened from the file '%s'%n", args[0]);
        try {
            if (args.length > 1) {
                System.out.printf("Local Config Storage initialized with the Client Key '%s'%n", args[1]);
                initializeStorage(storage, args[1], "dev.keepersecurity.com");
            }
            SecretsManagerOptions options = new SecretsManagerOptions(storage);
//            KeeperSecrets secrets = getSecrets(options);
            KeeperSecrets secrets = getSecrets(options, Arrays.asList("UlzQ-jKQTgQcEvpJI9vxxQ"));
            System.out.println(secrets.getRecords());

            // get the password from the first record
            KeeperRecord firstRecord = secrets.getRecords().get(0);
            List<String> firstRecordPassword = ((Password) firstRecord.getData().getField(Password.class)).getValue();
            System.out.println(firstRecordPassword.get(0));

            // download the file from the 3rd record
            KeeperFile file = secrets.getRecords().get(2).getFiles().get(0);
            byte[] fileBytes = downloadFile(file);
            try (FileOutputStream fos = new FileOutputStream(file.getData().getName())) {
                fos.write(fileBytes);
            }

            // update the password on the first record
            firstRecordPassword.replaceAll(x -> "aP1$t367QOCvL$eM$bG#");
            updateSecret(options, firstRecord);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
