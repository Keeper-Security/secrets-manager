package hello;

import com.keepersecurity.secretsManager.core.*;
import static com.keepersecurity.secretsManager.core.SecretsManager.*;
import static com.keepersecurity.secretsManager.core.Notation.*;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class App {

    private static class TestCryptoProvider implements CryptoProvider {

        static Provider p = new BouncyCastleFipsProvider();
//        static Provider p = new BouncyCastleProvider();

        public Provider getProvider() {
            return p;
        }

        public byte[] multiplyG(BigInteger s) {
            return ECNamedCurveTable.getByName("secp256r1").getG().multiply(s).getEncoded(false);
        }
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"");
            System.out.println("F.e. ./gradlew run --args=\"config.json US:EXAMPLE_ONE_TIME_TOKEN\"");
            System.out.println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%");
            return;
        }

// If working with initialized config, Secrets Manager does not need to call setCryptoProvider if the client already uses BouncyCastle or BouncyCastle FIPS
// If using one time token, Secrets Manager need to export the public key and needs a call to setCryptoProvider to wire the necessary logic

        Security.addProvider(new BouncyCastleFipsProvider());
//        Security.addProvider(new BouncyCastleProvider());
//        setCryptoProvider(new TestCryptoProvider());

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
//          KeeperSecrets secrets = getSecrets(options, Arrays.asList("RECORD_UID")); for a single record
            System.out.println(secrets.getRecords());

            // get the password from the first record
            KeeperRecord firstRecord = secrets.getRecords().get(0);
            String firstRecordPassword = firstRecord.getPassword();
            System.out.println(firstRecordPassword);

            // an alternate way to get the password
//          String password = getValue(secrets, "RECORD_UID/field/password");
//          System.out.println(password);

            // download the file from the 3rd record
            KeeperFile file = secrets.getRecords().get(2).getFileByName("acme.cer");
            if (file != null) {
                byte[] fileBytes = downloadFile(file);
                try (FileOutputStream fos = new FileOutputStream(file.getData().getName())) {
                    fos.write(fileBytes);
                }
            }

            // update the password on the first record
            firstRecord.updatePassword("N3wP4$$w0rd");
            updateSecret(options, firstRecord);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
