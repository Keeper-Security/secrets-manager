package com.keepersecurity.secretmanager.azurekv;

/*
*  _  __
* | |/ /___ ___ _ __  ___ _ _ (R)
* | ' </ -_) -_) '_ \/ -_) '_|
* |_|\_\___\___| .__/\___|_|
*              |_|
*
* Keeper Secrets Manager
* Copyright 2025 Keeper Security Inc.
* Contact: sm@keepersecurity.com
*/

/**
 * The {@code AzureSessionConfig} class represents the configuration required to
 * establish a session
 * with Azure services. It includes details such as the tenant ID, client ID,
 * client secret, and the
 * URL of the Azure Key Vault.
 */
public class AzureSessionConfig {

    private String tenantId;
    private String clientId;
    private String clientSecret;
    private String keyvaulturl;

    /**
     * Default constructor for {@code AzureSessionConfig}.
     */
    public AzureSessionConfig() {
    }

    /**
     * Constructs an {@code AzureSessionConfig} instance with the specified
     * parameters.
     *
     * @param tenantId     The Azure Active Directory tenant ID.
     * @param clientId     The client ID of the Azure application.
     * @param clientSecret The client secret associated with the Azure application.
     * @param keyvaulturl  The URL of the Azure Key Vault.
     */
    public AzureSessionConfig(String tenantId, String clientId, String clientSecret, String keyvaulturl) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.keyvaulturl = keyvaulturl;
    }

    /**
     * Gets the Azure Active Directory tenant ID.
     *
     * @return The tenant ID.
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Sets the Azure Active Directory tenant ID.
     *
     * @param tenantId The tenant ID to set.
     */
    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Gets the client ID of the Azure application.
     *
     * @return The client ID.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Sets the client ID of the Azure application.
     *
     * @param clientId The client ID to set.
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Gets the client secret associated with the Azure application.
     *
     * @return The client secret.
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Sets the client secret associated with the Azure application.
     *
     * @param clientSecret The client secret to set.
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * Gets the URL of the Azure Key Vault.
     *
     * @return The Key Vault URL.
     */
    public String getKeyVaultUrl() {
        return keyvaulturl;
    }

    /**
     * Sets the URL of the Azure Key Vault.
     *
     * @param keyvaulturl The Key Vault URL to set.
     */
    public void setKeyVaultUrl(String keyvaulturl) {
        this.keyvaulturl = keyvaulturl;
    }
}