package hello.secret.kt

import com.keepersecurity.secretsManager.core.*
import java.io.FileOutputStream

class App

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"")
        println("F.e. ./gradlew run --args=\"config.txt EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8\"")
        println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%")
        return
    }
    val storage: KeyValueStorage = LocalConfigStorage(args[0])
    System.out.printf("Local Config Storage opened from the file '%s'%n", args[0])
    try {
        if (args.size > 1) {
            System.out.printf("Local Config Storage initialized with the Client Key '%s'%n", args[1])
            initializeStorage(storage, args[1], "keepersecurity.com")
        }
        val options = SecretsManagerOptions(storage)
        val (records) = getSecrets(options)
        //            KeeperSecrets secrets = getSecrets(options, Arrays.asList("UlzQ-jKQTgQcEvpJI9vxxQ"));
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
        firstRecord.updatePassword("aP1\$t367QOCvL\$eM\$bG#")
        updateSecret(options, firstRecord)
    } catch (e: Exception) {
        println(e.message)
    }
}
