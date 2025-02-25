/*
 * Copyright 2024, Redis Ltd. and Contributors All rights reserved. Licensed under the MIT License.
 */
package redis.clients.authentication.entraid;

import java.util.Collections;
import java.util.Set;

import com.azure.identity.DefaultAzureCredential;

import redis.clients.authentication.core.TokenAuthConfig;
import redis.clients.authentication.core.TokenManagerConfig;

public class AzureTokenAuthConfigBuilder
        extends TokenAuthConfig.Builder<AzureTokenAuthConfigBuilder> implements AutoCloseable {
    public static final float DEFAULT_EXPIRATION_REFRESH_RATIO = 0.75F;
    public static final int DEFAULT_LOWER_REFRESH_BOUND_MILLIS = 2 * 60 * 1000;
    public static final int DEFAULT_TOKEN_REQUEST_EXECUTION_TIMEOUT_IN_MS = 1000;
    public static final int DEFAULT_MAX_ATTEMPTS_TO_RETRY = 5;
    public static final int DEFAULT_DELAY_IN_MS_TO_RETRY = 100;
    public static final Set<String> DEFAULT_SCOPES = Collections.singleton("https://redis.azure.com/.default");;

    private DefaultAzureCredential defaultAzureCredential;
    private Set<String> scopes = DEFAULT_SCOPES;
    private int tokenRequestExecTimeoutInMs;

    public AzureTokenAuthConfigBuilder() {
        this.expirationRefreshRatio(DEFAULT_EXPIRATION_REFRESH_RATIO)
                .lowerRefreshBoundMillis(DEFAULT_LOWER_REFRESH_BOUND_MILLIS)
                .tokenRequestExecTimeoutInMs(DEFAULT_TOKEN_REQUEST_EXECUTION_TIMEOUT_IN_MS)
                .maxAttemptsToRetry(DEFAULT_MAX_ATTEMPTS_TO_RETRY)
                .delayInMsToRetry(DEFAULT_DELAY_IN_MS_TO_RETRY);
    }

    public AzureTokenAuthConfigBuilder defaultAzureCredential(
            DefaultAzureCredential defaultAzureCredential) {
        this.defaultAzureCredential = defaultAzureCredential;
        return this;
    }

    public AzureTokenAuthConfigBuilder scopes(Set<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @Override
    public AzureTokenAuthConfigBuilder tokenRequestExecTimeoutInMs(
            int tokenRequestExecTimeoutInMs) {
        super.tokenRequestExecTimeoutInMs(tokenRequestExecTimeoutInMs);
        this.tokenRequestExecTimeoutInMs = tokenRequestExecTimeoutInMs;
        return this;
    }

    public TokenAuthConfig build() {
        super.identityProviderConfig(new AzureIdentityProviderConfig(defaultAzureCredential, scopes,
                tokenRequestExecTimeoutInMs));
        return super.build();
    }

    @Override
    public void close() throws Exception {
        defaultAzureCredential = null;
        scopes = null;
    }

    public static AzureTokenAuthConfigBuilder builder() {
        return new AzureTokenAuthConfigBuilder();
    }

    public static AzureTokenAuthConfigBuilder from(AzureTokenAuthConfigBuilder sample) {
        TokenAuthConfig tokenAuthConfig = TokenAuthConfig.Builder.from(sample).build();
        TokenManagerConfig tokenManagerConfig = tokenAuthConfig.getTokenManagerConfig();

        AzureTokenAuthConfigBuilder builder = (AzureTokenAuthConfigBuilder) new AzureTokenAuthConfigBuilder()
                .expirationRefreshRatio(tokenManagerConfig.getExpirationRefreshRatio())
                .lowerRefreshBoundMillis(tokenManagerConfig.getLowerRefreshBoundMillis())
                .tokenRequestExecTimeoutInMs(tokenManagerConfig.getTokenRequestExecTimeoutInMs())
                .maxAttemptsToRetry(tokenManagerConfig.getRetryPolicy().getMaxAttempts())
                .delayInMsToRetry(tokenManagerConfig.getRetryPolicy().getdelayInMs())
                .identityProviderConfig(tokenAuthConfig.getIdentityProviderConfig());
        builder.scopes = sample.scopes;
        return builder;
    }
}
