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

/**
 * Configuration class for Azure Identity Provider.
 * This class implements the {@link IdentityProviderConfig} interface and provides
 * a configuration for creating an {@link AzureIdentityProvider} instance.
 * 
 * <p>This class uses {@link DefaultAzureCredential} for authentication and allows
 * specifying scopes and a timeout(in milliseconds) for the identity provider.</p>
 * For most cases you will not need to use it directly since AzureTokenAuthConfigBuilder 
 * will do the work for you as shown in the example below:
 * <pre>
 * {@code
 * TokenAuthConfig config = AzureTokenAuthConfigBuilder.builder()
 *          .defaultAzureCredential(new DefaultAzureCredentialBuilder()).build();
 * } 
 * </pre>
 * <p>In you case you need your own implementation for relevant reasons, you can use it as follows:
 * <pre>
 * {@code
 * DefaultAzureCredential credential = new DefaultAzureCredentialBuilder().build();
 * Set<String> scopes = Set.of("https://redis.azure.com/.default");
 * AzureIdentityProviderConfig azureIDPConfig = new AzureIdentityProviderConfig(credential, scopes, 5000);
 * TokenAuthConfig config = AzureTokenAuthConfigBuilder.builder().identityProviderConfig(azureIDPConfig).build();
 * }
 * </pre>
 * 
 * For more information and details on how to use, please see:
 * https://github.com/redis/jedis/blob/master/docs/advanced-usage.md#token-based-authentication
 * https://github.com/redis/lettuce/blob/main/docs/user-guide/connecting-redis.md#microsoft-entra-id-authentication
 * 
 * @see IdentityProviderConfig
 * @see AzureIdentityProvider
 * @see DefaultAzureCredential
 */
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
