import { KmsCryptoClient, KmsManagementClient } from "oci-keymanagement/lib/client";
import { OCISessionConfig } from "./OciSessionConfig";

export class OciKmsClient {
  private ociKmsCryptoClient: KmsCryptoClient;
  private ociKmsManagementClient: KmsManagementClient;

  constructor(sessionConfig: OCISessionConfig) {
    this.ociKmsCryptoClient = new KmsCryptoClient({ authenticationDetailsProvider: sessionConfig.getProvider() });
    this.ociKmsCryptoClient.endpoint = sessionConfig.getKmsCryptoEndpoint();
    this.ociKmsManagementClient = new KmsManagementClient({authenticationDetailsProvider : sessionConfig.getProvider()});
    this.ociKmsManagementClient.endpoint = sessionConfig.getKmsManagementEndpoint()
  }

  public getCryptoClient(): KmsCryptoClient {
    return this.ociKmsCryptoClient;
  }

  public getManagementClient() :KmsManagementClient{
    return this.ociKmsManagementClient;
  }

}
