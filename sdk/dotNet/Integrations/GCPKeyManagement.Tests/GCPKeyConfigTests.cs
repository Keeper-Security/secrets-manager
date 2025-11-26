using NUnit.Framework;
using System;

namespace GCPKeyManagement.Tests
{
    [TestFixture]
    public class GCPKeyConfigTests
    {
        [TestFixture]
        public class ConstructorWithIndividualParameters
        {
            [Test]
            public void Should_Create_Config_With_Valid_Parameters()
            {
                // Given
                var keyName = "my-key";
                var keyRing = "my-keyring";
                var project = "my-project";
                var location = "us-central1";

                // When
                var config = new GCPKeyConfig(
                    keyName: keyName,
                    keyRing: keyRing,
                    project: project,
                    location: location);

                // Then
                Assert.That(config.KeyName, Is.EqualTo(keyName));
                Assert.That(config.KeyRing, Is.EqualTo(keyRing));
                Assert.That(config.Project, Is.EqualTo(project));
                Assert.That(config.Location, Is.EqualTo(location));
                Assert.That(config.KeyVersion, Is.EqualTo(""));
            }

            [Test]
            public void Should_Create_Config_With_KeyVersion()
            {
                // Given
                var keyVersion = "1";

                // When
                var config = new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1",
                    keyVersion: keyVersion);

                // Then
                Assert.That(config.KeyVersion, Is.EqualTo(keyVersion));
            }

            [Test]
            public void Should_Throw_When_KeyName_Is_Missing()
            {
                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1"));
            }

            [Test]
            public void Should_Throw_When_KeyRing_Is_Missing()
            {
                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(
                    keyName: "my-key",
                    project: "my-project",
                    location: "us-central1"));
            }

            [Test]
            public void Should_Throw_When_Project_Is_Missing()
            {
                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    location: "us-central1"));
            }

            [Test]
            public void Should_Throw_When_Location_Is_Missing()
            {
                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project"));
            }
        }

        [TestFixture]
        public class ConstructorWithResourceName
        {
            [Test]
            public void Should_Parse_Valid_Resource_Name()
            {
                // Given
                var resourceName = "projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1";

                // When
                var config = new GCPKeyConfig(resourceName: resourceName);

                // Then
                Assert.That(config.Project, Is.EqualTo("my-project"));
                Assert.That(config.Location, Is.EqualTo("us-central1"));
                Assert.That(config.KeyRing, Is.EqualTo("my-keyring"));
                Assert.That(config.KeyName, Is.EqualTo("my-key"));
                Assert.That(config.KeyVersion, Is.EqualTo("1"));
            }

            [Test]
            public void Should_Throw_For_Resource_Name_Without_Version()
            {
                // Given - resource name without version has fewer than 10 parts
                var resourceName = "projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key";

                // When/Then - source code requires at least 10 parts in resource name
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(resourceName: resourceName));
            }

            [Test]
            public void Should_Throw_For_Invalid_Resource_Name()
            {
                // Given
                var invalidResourceName = "invalid/path";

                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(resourceName: invalidResourceName));
            }

            [Test]
            public void Should_Throw_For_Resource_Name_With_Missing_Parts()
            {
                // Given
                var shortResourceName = "projects/my-project/locations";

                // When/Then
                Assert.Throws<ArgumentException>(() => new GCPKeyConfig(resourceName: shortResourceName));
            }
        }

        [TestFixture]
        public class ToKeyNameMethod
        {
            [Test]
            public void Should_Generate_Correct_Key_Name_Path()
            {
                // Given
                var config = new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1");

                // When
                var keyNamePath = config.ToKeyName();

                // Then
                Assert.That(keyNamePath, Is.EqualTo("projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key"));
            }
        }

        [TestFixture]
        public class ToResourceNameMethod
        {
            [Test]
            public void Should_Generate_Correct_Resource_Name_With_Version()
            {
                // Given
                var config = new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1",
                    keyVersion: "1");

                // When
                var resourceName = config.ToResourceName();

                // Then
                Assert.That(resourceName, Is.EqualTo("projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1"));
            }

            [Test]
            public void Should_Generate_Resource_Name_With_Empty_Version()
            {
                // Given
                var config = new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1");

                // When
                var resourceName = config.ToResourceName();

                // Then
                Assert.That(resourceName, Is.EqualTo("projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/"));
            }
        }

        [TestFixture]
        public class ToStringMethod
        {
            [Test]
            public void Should_Return_KeyName_And_Version()
            {
                // Given
                var config = new GCPKeyConfig(
                    keyName: "my-key",
                    keyRing: "my-keyring",
                    project: "my-project",
                    location: "us-central1",
                    keyVersion: "1");

                // When
                var result = config.ToString();

                // Then
                Assert.That(result, Is.EqualTo("my-key, 1"));
            }
        }

        [TestFixture]
        public class GCPSpecificFormats
        {
            [Test]
            public void Should_Accept_Valid_GCP_Project_Formats()
            {
                // Given - GCP project IDs
                var projects = new[]
                {
                    "my-project",
                    "project-123",
                    "my-company-prod",
                    "a1b2c3d4e5"
                };

                foreach (var project in projects)
                {
                    // When
                    var config = new GCPKeyConfig(
                        keyName: "key",
                        keyRing: "ring",
                        project: project,
                        location: "us-central1");

                    // Then
                    Assert.That(config.Project, Is.EqualTo(project));
                }
            }

            [Test]
            public void Should_Accept_Valid_GCP_Location_Formats()
            {
                // Given - GCP locations
                var locations = new[]
                {
                    "us-central1",
                    "us-east1",
                    "europe-west1",
                    "asia-northeast1",
                    "global"
                };

                foreach (var location in locations)
                {
                    // When
                    var config = new GCPKeyConfig(
                        keyName: "key",
                        keyRing: "ring",
                        project: "project",
                        location: location);

                    // Then
                    Assert.That(config.Location, Is.EqualTo(location));
                }
            }
        }
    }
}
