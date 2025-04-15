#nullable enable

using System;
using Oci.Common;
using Oci.Common.Auth;

public class OciSessionConfig
{
    private readonly string _ociConfigFileLocation;
    private readonly string _profile;
    private readonly string _kmsCryptoEndpoint;
    private readonly string _kmsManagementEndpoint;

    public OciSessionConfig(string ociConfigFileLocation, string? profile = null, string kmsCryptoEndpoint = "", string kmsManagementEndpoint = "")
    {
        _ociConfigFileLocation = ociConfigFileLocation ?? throw new ArgumentNullException(nameof(ociConfigFileLocation));
        _profile = profile ?? "DEFAULT";
        _kmsCryptoEndpoint = kmsCryptoEndpoint;
        _kmsManagementEndpoint = kmsManagementEndpoint;
    }

    public ConfigFileAuthenticationDetailsProvider GetProvider()
    {
        return new ConfigFileAuthenticationDetailsProvider(_ociConfigFileLocation, _profile);
    }

    public string GetKmsCryptoEndpoint()
    {
        return _kmsCryptoEndpoint;
    }

    public string GetKmsManagementEndpoint()
    {
        return _kmsManagementEndpoint;
    }
}
