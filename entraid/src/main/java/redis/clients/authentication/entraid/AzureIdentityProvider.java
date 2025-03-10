/*
 * Copyright 2024, Redis Ltd. and Contributors 
 * All rights reserved. 
 * 
 * Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Set;
import java.util.function.Supplier;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredential;
import redis.clients.authentication.core.IdentityProvider;
import redis.clients.authentication.core.Token;

/**
 * AzureIdentityProvider is an implementation of the IdentityProvider interface
 * that uses Azure's DefaultAzureCredential to obtain access tokens.
 * 
 * <p>This class is designed to work with Azure's identity platform to provide
 * authentication tokens for accessing Azure resources. It uses a 
 * DefaultAzureCredential to request tokens with specified scopes and a timeout(in milliseconds). 
 * For most cases you will not need to use it directly since AzureTokenAuthConfigBuilder 
 * will do the work for you as shown in the example below:
 * <pre>
 * {@code
 * TokenAuthConfig config = AzureTokenAuthConfigBuilder.builder()
 *          .defaultAzureCredential(new DefaultAzureCredential()).build();
 * }
 * </pre>
 * <p>In you case you need your own implementation for relevant reasons, you can use it as follows:
 * <pre>
 * {@code
 * Set<String> scopes = new HashSet<>(Arrays.asList("https://redis.azure.com/.default"));
 * AzureIdentityProvider provider = new AzureIdentityProvider(
 *      new DefaultAzureCredentialBuilder().build(), scopes, 5000);
 * TokenAuthConfig config = AzureTokenAuthConfigBuilder.builder().identityProviderConfig(()-> provider)).build();
 * }
 * </pre>
 * 
 * <p>Thread Safety: This class is thread-safe as long as the provided 
 * DefaultAzureCredential is thread-safe.
 * 
 * @see redis.clients.authentication.entraid.AzureTokenAuthConfigBuilder
 * @see com.azure.identity.DefaultAzureCredentialBuilder
 */

public final class AzureIdentityProvider implements IdentityProvider {

    private Supplier<AccessToken> accessTokenSupplier;

    public AzureIdentityProvider(DefaultAzureCredential defaultAzureCredential, Set<String> scopes,
            int timeout) {
        TokenRequestContext ctx = new TokenRequestContext()
                .setScopes(new ArrayList<String>(scopes));
        accessTokenSupplier = () -> defaultAzureCredential.getToken(ctx)
                .block(Duration.ofMillis(timeout));
    }

    @Override
    public Token requestToken() {
        return new JWToken(accessTokenSupplier.get().getToken());
    }
}
