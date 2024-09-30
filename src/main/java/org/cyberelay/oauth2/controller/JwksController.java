package org.cyberelay.oauth2.controller;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.ECKey;
import org.cyberelay.oauth2.config.EndPoints;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * Implementation of JWK Set Endpoint
 */
@RestController
public class JwksController {

    private final ECPublicKey publicKey;

    public JwksController(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @CrossOrigin
    @GetMapping(EndPoints.JWKS_URI)
    public Map<String, Object> getJwks() {
        JWK jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .keyID("ec-key-cyberelay") // Customize your key ID
                .build();

        JWKSet jwkSet = new JWKSet(jwk);
        return jwkSet.toJSONObject();
    }
}
