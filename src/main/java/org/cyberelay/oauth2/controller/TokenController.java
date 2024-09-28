package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.cyberelay.oauth2.dao.ClientRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(EndPoints.TOKEN)
public class TokenController {

    private final ClientRepository clientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    public TokenController(ClientRepository clientRepository,
                           OAuth2AuthorizationService authorizationService,
                           OAuth2TokenGenerator<?> tokenGenerator) {
        this.clientRepository = clientRepository;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @PostMapping
    public Map<String, Object> getToken(HttpServletRequest request) {
        // Extract client credentials from the request (basic authentication)
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (clientId == null || clientSecret == null) {
            throw new IllegalArgumentException("Invalid client credentials");
        }

        // Validate the client
        var client = clientRepository.findByClientId(clientId);
        if (client.isEmpty() || !client.get().getClientSecret().equals(clientSecret)) {
            throw new IllegalArgumentException("Invalid client credentials");
        }

        // Only handling the "client_credentials" grant type in this example
        if (!"client_credentials".equals(grantType)) {
            throw new IllegalArgumentException("Unsupported grant type");
        }

        var registeredClient = client.get().toRegisteredClient();
        // Generate the access token
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(new UsernamePasswordAuthenticationToken(clientId, clientSecret))
                .authorization(OAuth2Authorization.withRegisteredClient(registeredClient).build())
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2Token token = tokenGenerator.generate(tokenContext);

        if (token == null || !(token instanceof OAuth2AccessToken)) {
            throw new IllegalArgumentException("Unable to generate access token");
        }

        // Return the token response in JSON format
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", ((OAuth2AccessToken) token).getTokenValue());
        response.put("token_type", "Bearer");
        response.put("expires_in", ((OAuth2AccessToken) token).getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());

        return response;
    }
}
