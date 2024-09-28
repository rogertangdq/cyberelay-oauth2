package org.cyberelay.oauth2.util;

import org.springframework.data.util.Pair;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

public class ClientIdSecrets {

    private static final StringKeyGenerator ID_GENERATOR = new Base64StringKeyGenerator(32);
    private static final StringKeyGenerator SECRET_GENERATOR = new Base64StringKeyGenerator(64);

    private ClientIdSecrets() {
        // Prevent instantiation.
    }

    /**
     * Generate a ID-secret pair:
     * - The first one is the ID, the second one is the secret.
     * - The secret string is NOT encrypted which is expected to be done separately.
     */
    public static Pair<String, String> newClientIdSecret() {
        var id = "client." + ID_GENERATOR.generateKey();
        var secret = SECRET_GENERATOR.generateKey();
        return Pair.of(id, secret);
    }
}
