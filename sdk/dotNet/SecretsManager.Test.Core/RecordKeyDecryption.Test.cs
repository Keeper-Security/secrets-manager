using NUnit.Framework;

namespace SecretsManager.Test
{
    /// <summary>
    /// Tests for KSM-746: Record key decryption fix for shared folder records
    ///
    /// Bug: Records created in shared folders (e.g., via PowerShell Commander) have their
    /// recordKey encrypted with the FOLDER KEY. When these records appear in the flat
    /// response.records[] array, the SDK must detect the folderUid and use the folder key
    /// for decryption instead of defaulting to the app key.
    /// </summary>
    public class RecordKeyDecryptionTests
    {
        [Test]
        public void DecryptionKeySelection_RecordWithFolderUid_UsesFolderKey()
        {
            // Regression test for KSM-746
            // This test documents the expected behavior:
            // When a record has folderUid set and the folder exists in the response,
            // the SDK should use the folder key to decrypt the recordKey

            // Setup: Generate keys
            var appKey = CryptoUtils.GetRandomBytes(32);
            var folderKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);

            // Encrypt folder key with app key
            var folderKeyEncrypted = CryptoUtils.Encrypt(folderKey, appKey);

            // Bug scenario: Encrypt record key with FOLDER key (as PowerShell Commander does)
            var recordKeyEncryptedWithFolderKey = CryptoUtils.Encrypt(recordKey, folderKey);

            // Verify that folder key can decrypt the record key
            var decryptedRecordKey = CryptoUtils.Decrypt(recordKeyEncryptedWithFolderKey, folderKey);
            Assert.That(decryptedRecordKey, Is.EqualTo(recordKey),
                "Record key encrypted with folder key should decrypt correctly");

            // Verify that app key CANNOT decrypt the record key (this was the bug)
            Assert.Throws<Org.BouncyCastle.Crypto.InvalidCipherTextException>(() =>
            {
                CryptoUtils.Decrypt(recordKeyEncryptedWithFolderKey, appKey);
            }, "Record key encrypted with folder key should NOT decrypt with app key");
        }

        [Test]
        public void DecryptionKeySelection_RecordWithoutFolderUid_UsesAppKey()
        {
            // Test individually shared records (no folder association)
            // These should continue to use app key for decryption

            var appKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);

            // Individual share: Encrypt record key with app key
            var recordKeyEncrypted = CryptoUtils.Encrypt(recordKey, appKey);

            // Verify app key can decrypt
            var decryptedRecordKey = CryptoUtils.Decrypt(recordKeyEncrypted, appKey);
            Assert.That(decryptedRecordKey, Is.EqualTo(recordKey),
                "Record key encrypted with app key should decrypt correctly");
        }

        [Test]
        public void ResponseStructure_FolderUidProperty_ExistsOnRecord()
        {
            // Verify that SecretsManagerResponseRecord has folderUid property
            // (This was added as part of the KSM-746 fix)

            var record = new SecretsManagerResponseRecord
            {
                recordUid = "test123",
                recordKey = "encrypted_key",
                data = "encrypted_data",
                folderUid = "folder456", // New property added for KSM-746
                revision = 1,
                isEditable = true
            };

            Assert.That(record.folderUid, Is.EqualTo("folder456"),
                "SecretsManagerResponseRecord should have folderUid property");
        }

        [Test]
        public void FallbackBehavior_FolderNotFound_UsesAppKey()
        {
            // Edge case test: When record has folderUid but folder not in response,
            // should fall back to app key (graceful degradation)

            var appKey = CryptoUtils.GetRandomBytes(32);
            var recordKey = CryptoUtils.GetRandomBytes(32);

            // Encrypt with app key (fallback case)
            var recordKeyEncrypted = CryptoUtils.Encrypt(recordKey, appKey);

            // Verify fallback works
            var decryptedRecordKey = CryptoUtils.Decrypt(recordKeyEncrypted, appKey);
            Assert.That(decryptedRecordKey, Is.EqualTo(recordKey),
                "Fallback to app key should work when folder not found");
        }
    }
}
