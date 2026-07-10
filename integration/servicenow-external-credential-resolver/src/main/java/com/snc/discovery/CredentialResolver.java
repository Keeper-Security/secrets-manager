package com.snc.discovery;

import com.snc.discovery.keeper.KeeperCredentialResolver;

/**
 * Legacy resolver class name required by pre-Xanadu MID Servers, where every external credential
 * resolver JAR must expose {@code com.snc.discovery.CredentialResolver}. All behavior is inherited
 * from {@link KeeperCredentialResolver}.
 *
 * <p>This class ships only in the pre-Xanadu ("legacy") JAR variant. The Xanadu+ ("fqcn") JAR omits
 * it so the resolver can coexist with other vendors' resolvers (CyberArk, HashiCorp, Delinea, …),
 * which also ship {@code com.snc.discovery.CredentialResolver}. On Xanadu and newer, register the
 * resolver by the FQCN {@code com.snc.discovery.keeper.KeeperCredentialResolver} instead.</p>
 */
public class CredentialResolver extends KeeperCredentialResolver {
    public CredentialResolver() {
        super();
    }
}
