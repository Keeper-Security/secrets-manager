import { KeyManagementServiceClient } from "@google-cloud/kms";
import { GCPKeyValueStorageError } from "./error";
import pino from "pino";
import { getLogger } from "./Logger";
import { DEFAULT_LOG_LEVEL } from "./constants";
import { readFileSync } from "fs";

export class GCPKSMClient {
  private logger: pino.Logger;
  private KMSClient: KeyManagementServiceClient | null = null;


  /**
   * Initializes a GCP KMS client using the default configuration.
   *
   * By default, the GCP KMS client will use the Application Default Credentials
   * (ADC) to authenticate. The ADC will search for credentials in the following
   * order:
   * 1. The `GOOGLE_APPLICATION_CREDENTIALS` environment variable
   * 2. The `~/.config/gcloud/application_default_credentials.json` file
   * 3. The `~/.config/gcloud/legacy_credentials/CLIENT_ID`
   *    file if it contains a client ID and client secret
   * 4. On Google App Engine, the built-in service accounts
   * 5. On Google Compute Engine, the built-in service accounts
   *
   * If you want to use a different set of credentials, you can pass them in the
   * constructor.
   */
  constructor(logger?: pino.Logger) {
    this.KMSClient = new KeyManagementServiceClient();
    this.logger = logger == null ? getLogger(DEFAULT_LOG_LEVEL) : logger;
  }

  /**
   * Creates a new GCP KMS client using the specified credentials file.
   *
   * @param credentialsKeyFilePath - The file path to the JSON key file containing
   * the service account credentials. This file should be generated and downloaded
   * from the Google Cloud Console.
   *
   * This method sets up the KMS client with the provided credentials, allowing
   * it to authenticate and interact with Google Cloud KMS resources.
   *
   * @example
   * const client = new GCPKSMClient();
   * client.createClientFromCredentialsFile('path/to/credentials.json');
   */

  public createClientFromCredentialsFile(credentialsKeyFilePath: string) {
    this.logger.debug(`Creating KMS client using credentials file: ${credentialsKeyFilePath}`);

    const rawKeyFile = readFileSync(credentialsKeyFilePath, 'utf-8');
    const keyFileJson = JSON.parse(rawKeyFile);

    // No `scopes` option here: omitting it keeps the per-call credential a self-signed JWT
    // bound to the Cloud KMS request audience. Adding scopes switches to an OAuth access token
    // scoped to all of cloud-platform, usable against any Google API for its 1h life if leaked.
    this.KMSClient = new KeyManagementServiceClient({
      credentials: {
        client_email: keyFileJson.client_email,
        private_key: keyFileJson.private_key,
      },
    });

    return this;
  }


  /**
   * Creates a new GCP KMS client using the specified client email and private key.
   *
   * @param clientEmail - The email address associated with the service account.
   * @param privateKey - The private key corresponding to the service account.
   *
   * This method configures the KMS client with the provided credentials,
   * enabling authentication and interaction with Google Cloud KMS resources.
   *
   * @example
   * const client = new GCPKSMClient();
   * client.createClientUsingCredentials('foo@bar.com', '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----');
   */

  public createClientUsingCredentials(clientEmail: string, privateKey: string) {
    this.logger.debug(`Creating KMS client using credentials: ${clientEmail}`);
    // See the comment in createClientFromCredentialsFile: no `scopes` option, same reason.
    this.KMSClient = new KeyManagementServiceClient({
      credentials: {
        client_email: clientEmail,
        private_key: privateKey
      },
    });
    return this;
  }

  /**
   * Returns the KMS client.
   *
   * @returns The KMS client.
   */
  public getCryptoClient() {
    this.logger.debug("Getting KMS client");
    if (!this.KMSClient) {
      this.logger.error("KMS client not initialized. Neither createClientFromCredentialsFile nor createClientUsingCredentials have been called first.");
      throw new GCPKeyValueStorageError("KMS client not initialized. Please call createClientFromCredentialsFile or createClientUsingCredentials first.");
    }
    return this.KMSClient;
  }

  public async getToken() {
    this.logger.debug("Getting KMS client");
    if (!this.KMSClient) {
      this.logger.error("KMS client not initialized. Neither createClientFromCredentialsFile nor createClientUsingCredentials have been called first.");
      throw new GCPKeyValueStorageError("KMS client not initialized. Please call createClientFromCredentialsFile or createClientUsingCredentials first.");
    }
    try {
      const token = await this.KMSClient.auth.getAccessToken();
      return token ?? undefined;
    } catch (err: unknown) {
      // google-auth-library's error keeps the failed request's config, which can hold credential
      // material (a refresh token for authorized_user/impersonated ADC, a subject token for
      // external_account). Its own redactor strips grant_type/assertion/*secret*, but not
      // refresh_token, so the raw error must never cross this boundary. Pass on only the message.
      const reason = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to get a GCP access token: ${reason}`);
      throw new GCPKeyValueStorageError(`Failed to get a GCP access token: ${reason}`);
    }
  }
}
