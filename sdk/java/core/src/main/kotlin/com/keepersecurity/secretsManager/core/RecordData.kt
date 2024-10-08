@file:JvmName("RecordData")
@file:Suppress("unused")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class KeeperRecordData @JvmOverloads constructor(
    var title: String,
    val type: String,
    val fields: MutableList<KeeperRecordField>,
    var custom: MutableList<KeeperRecordField>? = null,
    var notes: String? = null
) {
    inline fun <reified T> getField(): T? {
        return (fields + custom).find { x -> x is T } as T
    }

    fun getField(clazz: Class<out KeeperRecordField>): KeeperRecordField? {
        return (fields + (custom ?: listOf())).find { x -> x.javaClass == clazz }
    }
}

@Serializable
sealed class KeeperRecordField {
    abstract val label: String?
}

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String? = null,
    val size: Long,
    val lastModified: Long
)

@Serializable
@SerialName("login")
data class Login @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>
) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class PasswordComplexity(
    var length: Int? = null,
    var caps: Int? = null,
    var lowercase: Int? = null,
    var digits: Int? = null,
    var special: Int? = null
)

@Serializable
@SerialName("password")
data class Password @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var enforceGeneration: Boolean? = null,
    var complexity: PasswordComplexity? = null,
    val value: MutableList<String>
) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("url")
data class Url @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

// "file" - obsolete and removed legacy field - "fldt_file": { key: 'file_or_photo', default: "File or Photo" },
@Serializable
@SerialName("fileRef")
data class FileRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("oneTimeCode")
data class OneTimeCode @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("otp")
data class OneTimePassword @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Name @JvmOverloads constructor( var first: String? = null, var middle: String? = null, var last: String? = null)

@Serializable
@SerialName("name")
data class Names @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Name>) : KeeperRecordField(){
    constructor(value: Name): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("birthDate")
data class BirthDate @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("date")
data class Date @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("expirationDate")
data class ExpirationDate @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Long>) : KeeperRecordField(){
    constructor(value: Long): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("text")
data class Text @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class SecurityQuestion @JvmOverloads constructor( var question: String? = null, var answer: String? = null)

@Serializable
@SerialName("securityQuestion")
data class SecurityQuestions @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<SecurityQuestion>
) : KeeperRecordField(){
    constructor(value: SecurityQuestion): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("multiline")
data class Multiline @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("email")
data class Email @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("cardRef")
data class CardRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("addressRef")
data class AddressRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("pinCode")
data class PinCode @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Phone @JvmOverloads constructor(

    /**
     * Region code. Ex. US
     */
    val region: String? = null,

    /**
     * Phone number. Ex. 510-222-5555
     */
    val number: String? = null,

    /**
     * Extension number. Ex. 9987
     */
    val ext: String? = null,

    /**
     * Phone number type. Ex. Mobile
     */
    val type: String? = null
)

@Serializable
@SerialName("phone")
data class Phones @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<Phone>) : KeeperRecordField(){
    constructor(value: Phone): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("secret")
data class HiddenField @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("note")
data class SecureNote @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("accountNumber")
data class AccountNumber @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: List<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
data class PaymentCard @JvmOverloads constructor(
    var cardNumber: String? = null,
    var cardExpirationDate: String? = null,
    var cardSecurityCode: String? = null
)

@Serializable
@SerialName("paymentCard")
data class PaymentCards @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<PaymentCard>) : KeeperRecordField(){
    constructor(value: PaymentCard): this(null, null, null, mutableListOf(value))
}

@Serializable
data class BankAccount @JvmOverloads constructor(
    var accountType: String? = null,
    var routingNumber: String? = null,
    var accountNumber: String? = null,
    var otherType: String? = null
)

@Serializable
@SerialName("bankAccount")
data class BankAccounts @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<BankAccount>) : KeeperRecordField() {
    constructor(value: BankAccount): this(null, null, null, mutableListOf(value))
}

@Serializable
data class KeyPair @JvmOverloads constructor(
    val publicKey: String? = null,
    val privateKey: String? = null,
)

@Serializable
@SerialName("keyPair")
data class KeyPairs @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<KeyPair>) : KeeperRecordField() {
    constructor(value: KeyPair): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Host @JvmOverloads constructor(
    val hostName: String? = null,
    val port: String? = null,
)

@Serializable
@SerialName("host")
data class Hosts @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Host>) : KeeperRecordField() {
    constructor(value: Host): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Address @JvmOverloads constructor(
    val street1: String? = null,
    val street2: String? = null,
    val city: String? = null,
    val state: String? = null,
    val country: String? = null,
    val zip: String? = null
)

@Serializable
@SerialName("address")
data class Addresses @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Address>) : KeeperRecordField() {
    constructor(value: Address): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("licenseNumber")
data class LicenseNumber @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField() {
    constructor(value: String): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("allowedSettings")
data class AllowedSettings @JvmOverloads constructor(
    val connections: Boolean? = null,
    val portForwards: Boolean? = null,
    val rotation: Boolean? = null,
    val sessionRecording: Boolean? = null,
    val typescriptRecording: Boolean? = null
)
@Serializable
data class PamResource @JvmOverloads constructor(
    val controllerUid: String? = null,
    val folderUid: String? = null,
    val resourceRef: MutableList<String>? = null,
    val allowedSettings: AllowedSettings? = null
)

@Serializable
@SerialName("pamResources")
data class PamResources @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<PamResource>) : KeeperRecordField() {
    constructor(value: PamResource): this(null, null, mutableListOf(value))
}

@Serializable
data class Schedule @JvmOverloads constructor(
    val type: String? = null,
    val cron: String? = null,
    // utcTime - replaced by time and tz
    val time: String? = null,
    val tz: String? = null,
    val weekday: String? = null,
    val intervalCount: Int? = null
)

@Serializable
@SerialName("schedule")
data class Schedules @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<Schedule>) : KeeperRecordField() {
    constructor(value: Schedule): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("checkbox")
data class Checkbox @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<Boolean>) : KeeperRecordField(){
    constructor(value: Boolean): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("databaseType")
data class DatabaseType @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("directoryType")
data class DirectoryType @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("recordRef")
data class RecordRef @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("pamHostname")
data class PamHostnames @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Host>) : KeeperRecordField() {
    constructor(value: Host): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("privateKey")
data class PrivateKey @JvmOverloads constructor(
    val crv: String? = null,
    val d: String? = null,
    val ext: Boolean? = null,
    @SerialName("key_ops") val keyOps: List<String>? = null,
    val kty: String? = null,
    val x: String? = null,
    val y: String? = null
)

@Serializable
data class Passkey @JvmOverloads constructor(
    val privateKey: PrivateKey? = null,
    val credentialId: String? = null,
    val signCount: Long? = null,
    val userId: String? = null,
    val relyingParty: String? = null,
    val username: String? = null,
    val createdDate: Long? = null
)

@Serializable
@SerialName("passkey")
data class Passkeys @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Passkey>) : KeeperRecordField() {
    constructor(value: Passkey): this(null, null, null, mutableListOf(value))
}

@Serializable
data class Script @JvmOverloads constructor(
    val fileRef: String? = null,
    val command: String? = null,
    val recordRef: MutableList<String>? = null,
)

@Serializable
@SerialName("script")
data class Scripts @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<Script>) : KeeperRecordField() {
    constructor(value: Script): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("isSSIDHidden")
data class IsSsidHidden @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<Boolean>) : KeeperRecordField(){
    constructor(value: Boolean): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("wifiEncryption")
data class WifiEncryption @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("dropdown")
data class Dropdown @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("rbiUrl")
data class RbiUrl @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

@Serializable
data class AppFiller @JvmOverloads constructor(
    val applicationTitle: String? = null,
    val contentFilter: String? = null,
    val macroSequence: String? = null,
)

@Serializable
@SerialName("appFiller")
data class AppFillers @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    var privacyScreen: Boolean? = null,
    val value: MutableList<AppFiller>) : KeeperRecordField() {
    constructor(value: AppFiller): this(null, null, null, mutableListOf(value))
}

@Serializable
@SerialName("connection")
data class PamRbiConnection @JvmOverloads constructor(
    val protocol: String? = null,
    val userRecords: MutableList<String>? = null,
    val allowUrlManipulation: Boolean? = null,
    val allowedUrlPatterns: String? = null,
    val allowedResourceUrlPatterns: String? = null,
    val httpCredentialsUid: String? = null,
    val autofillConfiguration: String? = null
)
@Serializable
data class PamRemoteBrowserSetting @JvmOverloads constructor(
    val connection: PamRbiConnection? = null,
)

@Serializable
@SerialName("pamRemoteBrowserSettings")
data class PamRemoteBrowserSettings @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<PamRemoteBrowserSetting>) : KeeperRecordField() {
    constructor(value: PamRemoteBrowserSetting): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("connection")
data class PamSettingsConnection @JvmOverloads constructor(
    val protocol: String? = null,
    val userRecords: MutableList<String>? = null,
    val security: String? = null,
    val ignoreCert: Boolean? = null,
    val resizeMethod: String? = null,
    val colorScheme: String? = null
)
@Serializable
@SerialName("portForward")
data class PamSettingsPortForward @JvmOverloads constructor(
    val reusePort: Boolean? = null,
    val port: String? = null
)
@Serializable
data class PamSetting @JvmOverloads constructor(
    val portForward: MutableList<PamSettingsPortForward>? = null,
    val connection: MutableList<PamSettingsConnection>? = null,
)

@Serializable
@SerialName("pamSettings")
data class PamSettings @JvmOverloads constructor(
    override val label: String? = null,
    var required: Boolean? = null,
    val value: MutableList<PamSetting>) : KeeperRecordField() {
    constructor(value: PamSetting): this(null, null, mutableListOf(value))
}

@Serializable
@SerialName("trafficEncryptionSeed")
data class TrafficEncryptionSeed @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

// List of retired field types:
// Replaced by trafficEncryptionSeed
@Serializable
@SerialName("trafficEncryptionKey")
internal data class TrafficEncryptionKey @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

// Deprecated for legacy/internal use only
@Serializable
@SerialName("pamProvider")
internal data class PamProvider @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}

// Deprecated for legacy/internal use only
@Serializable
@SerialName("controller")
internal data class Controller @JvmOverloads constructor(
    override var label: String? = null,
    var required: Boolean? = null,
    var value: MutableList<String>) : KeeperRecordField(){
    constructor(value: String): this(null, null, mutableListOf(value))
}
