package hello.secret.kt

import com.keepersecurity.secretsManager.core.*
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.FileOutputStream
import java.security.Security

class App

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"")
        println("F.e. ./gradlew run --args=\"config.json US:EXAMPLE_ONE_TIME_TOKEN\"")
        println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%")
        return
    }

    Security.addProvider(BouncyCastleFipsProvider())
//    Security.addProvider(BouncyCastleProvider());

    val storage: KeyValueStorage = LocalConfigStorage(args[0])
    println("Local Config Storage opened from the file ${args[0]}")
    try {
        if (args.size > 1) {
            println("Local Config Storage initialized with the Client Key ${args[1]}")
            // if your Keeper Account is in other region than US, update the hostname accordingly
            initializeStorage(storage, args[1], "keepersecurity.com")
        }
        val options = SecretsManagerOptions(storage)
//        val options = SecretsManagerOptions(storage, cachingPostFunction)
        val (records) = getSecrets(options)
        //            KeeperSecrets secrets = getSecrets(options, Arrays.asList("RECORD_UID"));
        println(records)

        // get the password from the first record
        val firstRecord = records[0]
        val firstRecordPassword = firstRecord.getPassword()
        println(firstRecordPassword)

        // download the file from the 3rd record
        val file = records[2].getFileByName("acme.cer")
        if (file != null) {
            val fileBytes = downloadFile(file)
            FileOutputStream(file.data.name).use { fos -> fos.write(fileBytes) }
        }

        // update the password on the first record
        firstRecord.updatePassword("N3wP4$$w0rd")
        updateSecret(options, firstRecord)
    } catch (e: Exception) {
        println(e.message)
    }
}
