/*
 * Copyright 2024, Redis Ltd. and Contributors
 * All rights reserved.
 *
 * Licensed under the MIT License.
 */
package redis.clients.authentication;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class TestContext {

    private static final String AZURE_CLIENT_ID = "AZURE_CLIENT_ID";
    private static final String AZURE_AUTHORITY = "AZURE_AUTHORITY";
    private static final String AZURE_CLIENT_SECRET = "AZURE_CLIENT_SECRET";
    private static final String AZURE_PRIVATE_KEY = "AZURE_PRIVATE_KEY";
    private static final String AZURE_CERT = "AZURE_CERT";
    private static final String AZURE_REDIS_SCOPES = "AZURE_REDIS_SCOPES";
    private static final String AZURE_USER_ASSIGNED_MANAGED_IDENTITY_CLIENT_ID = "AZURE_USER_ASSIGNED_MANAGED_IDENTITY_CLIENT_ID";

    private String clientId;
    private String authority;
    private String clientSecret;
    private PrivateKey privateKey;
    private X509Certificate cert;
    private Set<String> redisScopes;
    private String userAssignedManagedIdentityClientId;

    public static final TestContext DEFAULT = new TestContext();

    private TestContext() {

        this.clientId = System.getenv(AZURE_CLIENT_ID);
        this.authority = System.getenv(AZURE_AUTHORITY);
        this.clientSecret = System.getenv(AZURE_CLIENT_SECRET);
        this.userAssignedManagedIdentityClientId = System
                .getenv(AZURE_USER_ASSIGNED_MANAGED_IDENTITY_CLIENT_ID);
    }

    public TestContext(String clientId, String authority, String clientSecret,
            Set<String> redisScopes) {
        this.clientId = clientId;
        this.authority = authority;
        this.clientSecret = clientSecret;
        this.redisScopes = redisScopes;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAuthority() {
        return authority;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            this.privateKey = getPrivateKey(System.getenv(AZURE_PRIVATE_KEY));
        }
        return privateKey;
    }

    public X509Certificate getCert() {
        if (cert == null) {
            this.cert = getCert(System.getenv(AZURE_CERT));
        }
        return cert;
    }

    public Set<String> getRedisScopes() {
        if (redisScopes == null) {
            String redisScopesEnv = System.getenv(AZURE_REDIS_SCOPES);
            this.redisScopes = new HashSet<>(Arrays.asList(redisScopesEnv.split(";")));
        }
        return redisScopes;
    }

    public String getUserAssignedManagedIdentityClientId() {
        return userAssignedManagedIdentityClientId;
    }

    private PrivateKey getPrivateKey(String privateKey) {
        try {
            // Decode the base64 encoded key into a byte array
            byte[] decodedKey = Base64.getDecoder().decode(privateKey);

            // Generate the private key from the decoded byte array using PKCS8EncodedKeySpec
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Use the correct algorithm (e.g., "RSA", "EC", "DSA")
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private X509Certificate getCert(String cert) {
        try {
            // Convert the Base64 encoded string into a byte array
            byte[] encoded = java.util.Base64.getDecoder().decode(cert);

            // Create a CertificateFactory for X.509 certificates
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Generate the certificate from the byte array
            X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(encoded));
            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
