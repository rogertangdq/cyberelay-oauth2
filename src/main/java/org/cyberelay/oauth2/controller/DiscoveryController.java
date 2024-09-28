package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DiscoveryController {

    @GetMapping(EndPoints.DISCOVERY_URI)
    public Map<String, Object> openidConfiguration(HttpServletRequest request) {
        String issuerUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();

        Map<String, Object> config = new HashMap<>();
        config.put("issuer", issuerUrl);
        config.put("authorization_endpoint", issuerUrl + "/authorize");
        config.put("token_endpoint", issuerUrl + "/token");
        config.put("jwks_uri", issuerUrl + "/jwks.json");
        config.put("response_types_supported", new String[]{"code", "token", "id_token"});
        config.put("grant_types_supported", new String[]{"authorization_code", "client_credentials", "refresh_token"});
        config.put("scopes_supported", new String[]{"openid", "profile", "email"});
        config.put("subject_types_supported", new String[]{"public"});
        config.put("id_token_signing_alg_values_supported", new String[]{"RS256"});

        return config;
    }
}
