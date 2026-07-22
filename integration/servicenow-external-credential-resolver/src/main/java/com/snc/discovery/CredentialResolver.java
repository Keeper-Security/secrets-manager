package com.snc.discovery;

/**
 * Legacy resolver class name required by Xanadu and older MID Servers, where every external
 * credential resolver JAR must expose {@code com.snc.discovery.CredentialResolver}. All behavior is
 * inherited from {@link com.keepersecurity.secretsManager.CredentialResolver}.
 *
 * <p>This class ships only in the ("legacy") JAR variant. The ("fqcn") JAR omits it so the resolver
 * can coexist with other vendors' resolvers (CyberArk, HashiCorp, Delinea, …), which also ship
 * {@code com.snc.discovery.CredentialResolver}. On Yokohama (Patch 7+) and newer, register the
 * resolver by the FQCN {@code com.keepersecurity.secretsManager.CredentialResolver} instead.</p>
 */
public class CredentialResolver extends com.keepersecurity.secretsManager.CredentialResolver {
    public CredentialResolver() {
        super();
    }
}
