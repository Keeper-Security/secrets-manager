package com.keepersecurity.secretmanager.azurekv;


/**
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
**/

public class AzureSessionConfig {

	private String tenantId;
    private String clientId;
    private String clientSecret;
    private String keyvaulturl;
    
    public AzureSessionConfig() {}

    public AzureSessionConfig(String tenantId, String clientId, String clientSecret, String keyvaulturl) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.keyvaulturl = keyvaulturl;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }
    
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setKeyVaultUrl(String keyvaulturl) {
        this.keyvaulturl = keyvaulturl;
    }
    
    public String getKeyVaultUrl() {
        return keyvaulturl;
    }
}
