#nullable enable
using System;

public class GCPKeyConfig
{
    public string KeyName { get; }
    public string? KeyVersion { get; }
    public string KeyRing { get; }
    public string Project { get; }
    public string Location { get; }

    public GCPKeyConfig(
        string? resourceName = null,
        string? keyName = null,
        string? keyRing = null,
        string? project = null,
        string? location = null,
        string? keyVersion = null)
    {
        if (string.IsNullOrEmpty(resourceName))
        {
            KeyName = keyName ?? throw new ArgumentException("Key name is required.");
            KeyVersion = keyVersion ?? "";
            KeyRing = keyRing ?? throw new ArgumentException("Key ring is required.");
            Project = project ?? throw new ArgumentException("Project ID is required.");
            Location = location ?? throw new ArgumentException("Location is required.");
        }
        else
        {
            var parts = resourceName.Split('/');

            if (parts.Length < 10)
            {
                throw new ArgumentException("Invalid KMS resource path.");
            }

            Project = parts[1];
            Location = parts[3];
            KeyRing = parts[5];
            KeyName = parts[7];
            KeyVersion = parts.Length > 9 ? parts[9] : "";
        }

        if (string.IsNullOrEmpty(KeyName) || string.IsNullOrEmpty(KeyRing) ||
            string.IsNullOrEmpty(Project) || string.IsNullOrEmpty(Location))
        {
            throw new ArgumentException("Invalid KMS resource path.");
        }
    }

    public override string ToString()
    {
        return $"{KeyName}, {KeyVersion}";
    }

    public string ToKeyName()
    {
        return $"projects/{Project}/locations/{Location}/keyRings/{KeyRing}/cryptoKeys/{KeyName}";
    }

    public string ToResourceName()
    {
        return $"projects/{Project}/locations/{Location}/keyRings/{KeyRing}/cryptoKeys/{KeyName}/cryptoKeyVersions/{KeyVersion}";
    }
}
