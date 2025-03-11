/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Set;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredential;

import reactor.core.publisher.Mono;
import redis.clients.authentication.entraid.AzureIdentityProvider;
import redis.clients.authentication.entraid.AzureIdentityProviderConfig;
import redis.clients.authentication.entraid.AzureTokenAuthConfigBuilder;

public class AzureIdentityProviderUnitTests {
    @Test
    public void testAzureTokenAuthConfigBuilder() {
        DefaultAzureCredential mockCredential = mock(DefaultAzureCredential.class);
        Set<String> scopes = AzureTokenAuthConfigBuilder.DEFAULT_SCOPES;
        int timeout = 2000;

        try (MockedConstruction<AzureIdentityProviderConfig> mockedConstructor = mockConstruction(
                AzureIdentityProviderConfig.class,
                (mock, context) -> {
                    assertEquals(mockCredential, context.arguments().get(0));
                    assertEquals(scopes, context.arguments().get(1));
                    assertEquals(timeout, context.arguments().get(2));
                })) {
            AzureTokenAuthConfigBuilder.builder().defaultAzureCredential(mockCredential).scopes(scopes)
                    .tokenRequestExecTimeoutInMs(timeout).build();
        }
    }

    public void testAzureIdentityProviderConfig() {
        DefaultAzureCredential mockCredential = mock(DefaultAzureCredential.class);
        Set<String> scopes = AzureTokenAuthConfigBuilder.DEFAULT_SCOPES;
        int timeout = 2000;

        try (MockedConstruction<AzureIdentityProvider> mockedConstructor = mockConstruction(
                AzureIdentityProvider.class,
                (mock, context) -> {
                    assertEquals(mockCredential, context.arguments().get(0));
                    assertEquals(scopes, context.arguments().get(1));
                    assertEquals(timeout, context.arguments().get(2));
                })) {
            new AzureIdentityProviderConfig(mockCredential, scopes, timeout).getProvider();
        }
    }

    @Test
    public void testRequestWithMockCredential() {
        String token = JWT.create().withExpiresAt(new Date(System.currentTimeMillis()
                - 1000))
                .withClaim("oid", "user1").sign(Algorithm.none());

        AccessToken t = new AccessToken(token, OffsetDateTime.now());
        Mono<AccessToken> monoToken = Mono.just(t);
        DefaultAzureCredential mockCredential = mock(DefaultAzureCredential.class);
        when(mockCredential.getToken(any(TokenRequestContext.class))).thenReturn(monoToken);
        new AzureIdentityProviderConfig(mockCredential,
                AzureTokenAuthConfigBuilder.DEFAULT_SCOPES, 0).getProvider().requestToken();

        ArgumentCaptor<TokenRequestContext> argument = ArgumentCaptor.forClass(TokenRequestContext.class);

        verify(mockCredential, atLeast(1)).getToken(argument.capture());
        AzureTokenAuthConfigBuilder.DEFAULT_SCOPES
                .forEach((item) -> assertTrue(argument.getValue().getScopes().contains(item)));
    }
}
