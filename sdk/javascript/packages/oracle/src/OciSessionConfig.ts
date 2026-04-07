import { ConfigFileAuthenticationDetailsProvider } from "oci-common";

export class OCISessionConfig {
  ociConfigFileLocation: string;
  profile?: string;
  ksmCryptoEndpoint: string;
  ksmManagementEndpoint: string;

  constructor(
    ociConfigFileLocation: string,
    profile: string | null,
    kmsCryptoEndpoint: string,
    ksmManagementEndpoint : string
  ) {
    this.ociConfigFileLocation = ociConfigFileLocation;
    this.profile = profile || "DEFAULT";
    this.ksmCryptoEndpoint = kmsCryptoEndpoint;
    this.ksmManagementEndpoint = ksmManagementEndpoint;
  }

  public getProvider(): ConfigFileAuthenticationDetailsProvider {
    return new ConfigFileAuthenticationDetailsProvider(this.ociConfigFileLocation, this.profile);
  }

  public getKmsCryptoEndpoint(): string {
    return this.ksmCryptoEndpoint;
  }

  public getKmsManagementEndpoint(): string {
    return this.ksmManagementEndpoint;
  }
}
