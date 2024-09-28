package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DiscoveryController {

    @CrossOrigin
    @GetMapping(EndPoints.DISCOVERY_URI)
    public Map<String, Object> openidConfiguration() {
        var baseUrlBuilder = ServletUriComponentsBuilder.fromCurrentRequestUri().replacePath(null);

        Map<String, Object> config = new HashMap<>();
        config.put("issuer", baseUrlBuilder.build().toUriString());
        config.put("authorization_endpoint", baseUrlBuilder.replacePath(EndPoints.AUTHORIZATION).build().toUriString());
        config.put("token_endpoint", baseUrlBuilder.replacePath(EndPoints.TOKEN).build().toUriString());
        config.put("jwks_uri", baseUrlBuilder.replacePath(EndPoints.JWKS_URI).build().toUriString());
        config.put("response_types_supported", new String[]{"code", "token", "id_token"});
        config.put("grant_types_supported", new String[]{"authorization_code", "client_credentials", "refresh_token"});
        config.put("scopes_supported", new String[]{"openid", "profile", "email"});
        config.put("subject_types_supported", new String[]{"public"});
        config.put("id_token_signing_alg_values_supported", new String[]{"RS256"});

        return config;
    }
}
