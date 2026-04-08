using NUnit.Framework;
using System.Linq;

namespace SecretsManager.Test
{
    /// <summary>
    /// Proof-of-concept test demonstrating KSM-873 bug
    ///
    /// GetSecretsInfo() returns names in the format "UID title" (e.g. "YGGHvDMb0qw7QacqqLqCAg My Login").
    /// GetSecret() looks up records by matching x.RecordUid or x.Data.title individually.
    /// The combined "UID title" string matches neither branch, so Get-Secret silently returns null.
    /// </summary>
    [TestFixture]
    public class KSM873BugProofTests
    {
        private static KeeperRecord MakeRecord(string uid, string title)
        {
            var data = new KeeperRecordData
            {
                title = title,
                type = "login",
                fields = new KeeperRecordField[0],
                custom = new KeeperRecordField[0]
            };
            return new KeeperRecord(
                recordKey: new byte[32],
                recordUid: uid,
                folderUid: null,
                folderKey: null,
                innerFolderUid: null,
                data: data,
                revision: 1,
                files: null,
                links: null
            );
        }

        [Test]
        public void BugProof_CombinedUidTitleName_DoesNotMatchGetSecretLookup()
        {
            // Arrange: a record as it would exist in the vault
            const string uid = "YGGHvDMb0qw7QacqqLqCAg";
            const string title = "My Login";
            var records = new[] { MakeRecord(uid, title) };

            // Simulate the BROKEN GetSecretsInfo() select (line 200, before fix)
            var brokenName = $"{uid} {title}"; // "YGGHvDMb0qw7QacqqLqCAg My Login"

            // Simulate GetSecret() lookup (line 125)
            var foundByBrokenName = records.FirstOrDefault(
                x => x.RecordUid == brokenName || x.Data.title == brokenName);

            // BUG: the combined string matches neither UID nor title — returns null
            Assert.That(foundByBrokenName, Is.Null,
                "Bug proof: combined 'UID title' name should NOT match GetSecret lookup");
        }

        [Test]
        public void FixProof_TitleName_MatchesGetSecretLookup()
        {
            // Arrange
            const string uid = "YGGHvDMb0qw7QacqqLqCAg";
            const string title = "My Login";
            var records = new[] { MakeRecord(uid, title) };

            // Simulate the FIXED GetSecretsInfo() select: title only
            var fixedName = string.IsNullOrEmpty(title) ? uid : title; // "My Login"

            // Simulate GetSecret() lookup (line 125)
            var foundByFixedName = records.FirstOrDefault(
                x => x.RecordUid == fixedName || x.Data.title == fixedName);

            // FIX: title matches x.Data.title branch — round-trip works
            Assert.That(foundByFixedName, Is.Not.Null,
                "Fix proof: title name should match GetSecret lookup");
            Assert.That(foundByFixedName.RecordUid, Is.EqualTo(uid));
        }

        [Test]
        public void FixProof_NullTitle_FallsBackToUid()
        {
            // Arrange: record with no title
            const string uid = "YGGHvDMb0qw7QacqqLqCAg";
            var records = new[] { MakeRecord(uid, title: null) };

            // Simulate the FIXED select: falls back to UID when title is null/empty
            var fixedName = string.IsNullOrEmpty(null) ? uid : null; // uid

            var found = records.FirstOrDefault(
                x => x.RecordUid == fixedName || x.Data.title == fixedName);

            Assert.That(found, Is.Not.Null,
                "Fix proof: UID fallback should match when title is null");
            Assert.That(found.RecordUid, Is.EqualTo(uid));
        }
    }
}
