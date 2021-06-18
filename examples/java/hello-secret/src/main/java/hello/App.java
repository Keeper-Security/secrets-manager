package hello;

import com.keepersecurity.secretsManager.core.KeyValueStorage;
import com.keepersecurity.secretsManager.core.LocalConfigStorage;
import com.keepersecurity.secretsManager.core.KeeperSecrets;
import static com.keepersecurity.secretsManager.core.SecretsManager.getSecrets;
import static com.keepersecurity.secretsManager.core.SecretsManager.initializeStorage;

public class App {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"");
            System.out.println("F.e. ./gradlew run --args=\"config.txt EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8\"");
            System.out.println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%");
            return;
        }
        KeyValueStorage storage = new LocalConfigStorage(args[0]);
        System.out.println(String.format("Local Config Storage opened from the file '%s'", args[0]));
        try {
            if (args.length > 1) {
                System.out.println(String.format("Local Config Storage initialized with the Client Key '%s'", args[1]));
                initializeStorage(storage, args[1], "dev.keepersecurity.com");
            }
            KeeperSecrets secrets = getSecrets(storage, null);
            System.out.println(secrets);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
