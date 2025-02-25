/*
 * Copyright 2024, Redis Ltd. and Contributors All rights reserved. Licensed under the MIT License.
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
