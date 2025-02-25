/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.util.Set;
import java.util.function.Supplier;

import com.azure.identity.DefaultAzureCredential;

import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.IdentityProviderConfig;

public final class AzureIdentityProviderConfig implements IdentityProviderConfig {

    private final Supplier<IdentityProvider> providerSupplier;

    public AzureIdentityProviderConfig(DefaultAzureCredential defaultAzureCredential, Set<String> scopes, int timeout) {
        providerSupplier = () -> new AzureIdentityProvider(defaultAzureCredential, scopes, timeout);
    }

    @Override
    public IdentityProvider getProvider() {
        return providerSupplier.get();
    }
}
