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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
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

    public record TokenRequest(String client_id,
                               String client_secret,
                               String code,
                               String code_verifier,
                               String grant_type) {
        public TokenRequest withClientId(String clientId) {
            return new TokenRequest(clientId, this.client_secret, this.code, this.code_verifier, this.grant_type);
        }

        public TokenRequest withClientSecret(String clientSecret) {
            return new TokenRequest(this.client_id, clientSecret, this.code, this.code_verifier, this.grant_type);
        }
    }

    @PostMapping
    @CrossOrigin
    public Map<String, Object> getToken(@ModelAttribute TokenRequest request) {
        // Customization for test kit
        // Fill in default client to ensure client/clientSecret not absent.
        if (request.client_id == null || request.client_secret == null) {
            LOG.warn("Token request has no client_id, default client ID is used");
            request = request
                    .withClientId(defaultClient.getClientId())
                    .withClientSecret(defaultClient.getClientSecret());
        }

        if (request.code_verifier == null) {
            throw new IllegalArgumentException("Invalid code verifier");
        }

        // Validate the client
        var clientOpt = clientRepository.findByClientId(request.client_id);
        if (clientOpt.isEmpty() || !clientOpt.get().getClientSecret().equals(request.client_secret)) {
            throw new IllegalArgumentException("Invalid client credentials");
        }

        // Only handling the "authorization_code" grant type at this moment
        if (!"authorization_code".equals(request.grant_type)) {
            throw new IllegalArgumentException("Unsupported grant type: " + request.grant_type);
        }

        // Validate authorization code
        var code = authorizationService.findByToken(request.code, new OAuth2TokenType(OAuth2ParameterNames.CODE));
        if (code == null) {
            throw new IllegalArgumentException("Invalid authorization code");
        }

        var codeChallenge = (String) code.getAttribute("codeChallenge");
        var codeChallengeMethod = (String) code.getAttribute("codeChallengeMethod");
        if (codeChallenge == null || codeChallengeMethod == null) {
            throw new IllegalArgumentException("Code challenge or code challenge method not found");
        }

        if (!verifyCodeChallenge(request.code_verifier, codeChallenge, codeChallengeMethod)) {
            throw new IllegalArgumentException("Invalid code verifier");
        }

        var registeredClient = clientOpt.get().toRegisteredClient();
        var authorization = OAuth2Authorization.from(code)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();

        // Generate the access token
        var tokenContext = DefaultOAuth2TokenContext
                .builder()
                .registeredClient(registeredClient)
                .principal(new UsernamePasswordAuthenticationToken(request.client_id, request.client_secret))
                .authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(code.getAuthorizedScopes())
                .build();

        OAuth2Token accessToken = tokenGenerator.generate(tokenContext);
        authorization = OAuth2Authorization.from(authorization).token(accessToken).build();
        authorizationService.save(authorization);

        if (!(accessToken instanceof OAuth2AccessToken)) {
            throw new IllegalArgumentException("Unable to generate access token");
        }

        // Return the token response in JSON format
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", accessToken.getTokenValue());
        response.put("token_type", "Bearer");
        response.put("expires_in", accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());

        return response;
    }

    private boolean verifyCodeChallenge(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        try {
            switch (codeChallengeMethod.toLowerCase()) {
                case "s256":
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                    // Base64 URL-encode the hash
                    String encodedHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                    // Compare with the original code_challenge
                    return encodedHash.equals(codeChallenge);
                case "plain":
                    return codeVerifier.equals(codeChallenge);
                default:
                    throw new IllegalArgumentException("Unsupported code_challenge_method: " + codeChallengeMethod);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error while verifying code challenge: " + e.getMessage(), e);
        }
    }
}
