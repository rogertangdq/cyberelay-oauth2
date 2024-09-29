package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.cyberelay.oauth2.dao.ClientRepository;
import org.cyberelay.oauth2.model.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(EndPoints.TOKEN)
public class TokenController {
    private static final Logger LOG = LoggerFactory.getLogger(TokenController.class);

    private final ClientRepository clientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    private final Client defaultClient;

    public TokenController(ClientRepository clientRepository,
                           OAuth2AuthorizationService authorizationService,
                           OAuth2TokenGenerator<?> tokenGenerator,
                           @Qualifier("DEFAULT_CLIENT") Client defaultClient) {
        this.clientRepository = clientRepository;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.defaultClient = defaultClient;
    }

    public record TokenRequest(String client_id, String client_secret, String grant_type) {
        public TokenRequest withClientId(String clientId) {
            return new TokenRequest(clientId, this.client_secret, this.grant_type);
        }

        public TokenRequest withClientSecret(String clientSecret) {
            return new TokenRequest(this.client_id, clientSecret, this.grant_type);
        }
    }

    @PostMapping
    @CrossOrigin
    public Map<String, Object> getToken(@ModelAttribute TokenRequest request) {
        // Customization for test kit to ensure client/clientSecret not absent.
        if (request.client_id == null || request.client_secret == null) {
            LOG.warn("Token request has no client_id, default client ID is used");
            request = request.withClientId(defaultClient.getClientId())
                    .withClientSecret(defaultClient.getClientSecret());
        }

        // Validate the client
        var clientOpt = clientRepository.findByClientId(request.client_id);
        if (clientOpt.isEmpty() || !clientOpt.get().getClientSecret().equals(request.client_secret)) {
            throw new IllegalArgumentException("Invalid client credentials");
        }

        // Only handling the "authorization_code" grant type at this moment
        if (!"authorization_code".equals(request.grant_type)) {
            throw new IllegalArgumentException("Unsupported grant type: "  + request.grant_type);
        }

        var registeredClient = clientOpt.get().toRegisteredClient();
        // Generate the access token
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext
                .builder()
                .registeredClient(registeredClient)
                .principal(new UsernamePasswordAuthenticationToken(request.client_id, request.client_secret))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorization(OAuth2Authorization.withRegisteredClient(registeredClient).build())
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2Token token = tokenGenerator.generate(tokenContext);

        if (!(token instanceof OAuth2AccessToken)) {
            throw new IllegalArgumentException("Unable to generate access token");
        }

        // Return the token response in JSON format
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", token.getTokenValue());
        response.put("token_type", "Bearer");
        response.put("expires_in", token.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());

        return response;
    }
}
