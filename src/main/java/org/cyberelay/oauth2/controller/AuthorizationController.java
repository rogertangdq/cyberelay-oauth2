package org.cyberelay.oauth2.controller;

import org.apache.commons.lang3.StringUtils;
import org.cyberelay.oauth2.config.EndPoints;
import org.cyberelay.oauth2.dao.ClientRepository;
import org.cyberelay.oauth2.model.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Set;

/**
 * Implementation of Authorization Endpoint
 */
@Controller
@RequestMapping(EndPoints.AUTHORIZATION)
public class AuthorizationController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationController.class);
    private static final Set<String> VALID_CHALLENGE_METHODS = Set.of("s256", "plain");
    private final ClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final Client defaultClient;

    public AuthorizationController(ClientRepository registeredClientRepository,
                                   OAuth2AuthorizationService authorizationService,
                                   OAuth2TokenGenerator<?> tokenGenerator,
                                   @Qualifier("DEFAULT_CLIENT") Client defaultClient) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.defaultClient = defaultClient;
    }

    public record AuthorizeRequest(String client_id,
                                   String redirect_uri,
                                   String response_type,
                                   String response_mode,
                                   String scope,
                                   String code_challenge,
                                   String code_challenge_method,
                                   String principalName,
                                   String state) {
        public AuthorizeRequest withClientId(String client_id) {
            return new AuthorizeRequest(
                    client_id,
                    this.redirect_uri,
                    this.response_type,
                    this.response_mode,
                    this.scope,
                    this.code_challenge,
                    this.code_challenge_method,
                    this.principalName,
                    this.state
            );
        }

        public Set<String> getScopes() {
            return Set.of(StringUtils.split(scope, ","));
        }
    }

    @GetMapping
    public String authorize(@ModelAttribute AuthorizeRequest request, Model model) {
        if (StringUtils.isEmpty(request.client_id)) {
            // Customization for the test kit which has no client ID
            LOG.warn("Authorization request has no client_id, default client ID is used");
            request = request.withClientId(defaultClient.getClientId());
        }

        if (registeredClientRepository.findByClientId(request.client_id).isEmpty()) {
            throw new IllegalArgumentException("Invalid client_id");
        }

        // Get the current login user info
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LOG.info("authentication: {}", authentication);

        model.addAttribute("clientId", request.client_id);
        model.addAttribute("redirectUri", request.redirect_uri);
        model.addAttribute("responseType", request.response_type);
        model.addAttribute("responseMode", request.response_mode);
        model.addAttribute("scope", request.scope);
        model.addAttribute("codeChallenge", request.code_challenge);
        model.addAttribute("codeChallengeMethod", request.code_challenge_method);
        model.addAttribute("state", request.state);
        model.addAttribute("principalName", authentication.getName());

        return "authorize";
    }

    @PostMapping
    public String approveAuthorization(@ModelAttribute AuthorizeRequest request) {
        var clientOpt = registeredClientRepository.findByClientId(request.client_id);
        if (clientOpt.isEmpty()) {
            throw new IllegalArgumentException("Invalid client_id");
        }

        // TODO what if it's NON-PKCE flow?
        if (request.code_challenge == null || request.code_challenge_method == null) {
            throw new IllegalArgumentException("Code challenge or code challenge method not found");
        }

        if (!VALID_CHALLENGE_METHODS.contains(request.code_challenge_method.toLowerCase())) {
            throw new IllegalArgumentException("Invalid code challenge method: " + request.code_challenge_method);
        }

        var registeredClient = clientOpt.get().toRegisteredClient();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        var authorization = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(authentication.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute("codeChallenge", request.code_challenge)
                .attribute("codeChallengeMethod", request.code_challenge_method)
                .authorizedScopes(request.getScopes())
                .build();
        var tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(authorization)
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorization.getAuthorizedScopes())
                .authorizationGrantType(authorization.getAuthorizationGrantType())
                .build();
        var authorizationCode = tokenGenerator.generate(tokenContext);
        // Update authorization
        authorization = OAuth2Authorization.from(authorization).token(authorizationCode).build();
        authorizationService.save(authorization);
        if (authorizationCode == null) {
            throw new IllegalStateException("Authorization code not generated");
        }
        var code = authorizationCode.getTokenValue();

        String redirectUrl = request.redirect_uri + "?code=" + code + "&state=" + request.state;
        return "redirect:" + redirectUrl;
    }
}
