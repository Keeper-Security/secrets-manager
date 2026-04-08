using NUnit.Framework;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace SecretsManager.Test
{
    /// <summary>
    /// Proof-of-concept test demonstrating KSM-874 bug
    ///
    /// SecretManagement.Keeper.Extension.psd1 declared Set-KeeperVault in FunctionsToExport
    /// but no such function existed in SecretManagement.Keeper.Extension.psm1.
    /// Any call to Set-KeeperVault produced a hard terminating error.
    ///
    /// After the fix: every name in FunctionsToExport has a matching function definition in the psm1.
    /// </summary>
    [TestFixture]
    public class KSM874BugProofTests
    {
        private static readonly string PsmPath = Path.GetFullPath(
            Path.Combine(
                TestContext.CurrentContext.TestDirectory,
                "../../../../../../sdk/dotNet/SecretManagement.Keeper/SecretManagement.Keeper.Extension/SecretManagement.Keeper.Extension.psm1"));

        private static readonly string PsdPath = Path.GetFullPath(
            Path.Combine(
                TestContext.CurrentContext.TestDirectory,
                "../../../../../../sdk/dotNet/SecretManagement.Keeper/SecretManagement.Keeper.Extension/SecretManagement.Keeper.Extension.psd1"));

        private static string[] GetExportedFunctions()
        {
            var psd = File.ReadAllText(PsdPath);
            var match = Regex.Match(psd, @"FunctionsToExport\s*=\s*(.+)");
            if (!match.Success) return new string[0];
            return Regex.Matches(match.Groups[1].Value, @"'(\w[\w-]*)'")
                .Cast<Match>()
                .Select(m => m.Groups[1].Value)
                .ToArray();
        }

        private static string[] GetDefinedFunctions()
        {
            var psm = File.ReadAllText(PsmPath);
            return Regex.Matches(psm, @"^function\s+([\w-]+)", RegexOptions.Multiline)
                .Cast<Match>()
                .Select(m => m.Groups[1].Value)
                .ToArray();
        }

        [Test]
        public void AllExportedFunctions_HaveImplementations()
        {
            var exported = GetExportedFunctions();
            var defined = GetDefinedFunctions();

            var missing = exported.Except(defined).ToArray();

            Assert.That(missing, Is.Empty,
                $"FunctionsToExport lists functions with no implementation in psm1: {string.Join(", ", missing)}");
        }
    }
}
