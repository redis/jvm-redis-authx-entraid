/*
 * Copyright 2024, Redis Ltd. and Contributors 
 * All rights reserved. 
 * 
 * Licensed under the MIT License.
 */
package redis.clients.authentication;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;

import redis.clients.authentication.core.Token;
import redis.clients.authentication.entraid.AzureIdentityProvider;
import redis.clients.authentication.entraid.AzureTokenAuthConfigBuilder;

public class AzureIdentityProviderIntegrationTests {

        @Test
        public void requestTokenWithDefaultAzureCredential() {
                // ensure environment variables are set
                String client_id = System.getenv(TestContext.AZURE_CLIENT_ID);
                assertNotNull(client_id);
                assertFalse(client_id.isEmpty());
                String clientSecret = System.getenv(TestContext.AZURE_CLIENT_SECRET);
                assertNotNull(clientSecret);
                assertFalse(clientSecret.isEmpty());
                String tenantId = System.getenv("AZURE_TENANT_ID");
                assertNotNull(tenantId);
                assertFalse(tenantId.isEmpty());

                DefaultAzureCredential defaultAzureCredential = new DefaultAzureCredentialBuilder().build();
                Token token = new AzureIdentityProvider(defaultAzureCredential,
                                AzureTokenAuthConfigBuilder.DEFAULT_SCOPES, 2000).requestToken();
                assertNotNull(token.getValue());
        }
}
