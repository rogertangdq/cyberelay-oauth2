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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(EndPoints.AUTHORIZATION)
public class AuthorizationController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationController.class);

    private final ClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    private final Client defaultClient;

    public AuthorizationController(ClientRepository registeredClientRepository,
                                   OAuth2AuthorizationService authorizationService,
                                   @Qualifier("DEFAULT_CLIENT") Client defaultClient) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.defaultClient = defaultClient;
    }

    public record AuthorizeRequest(String client_id,
                                   String redirect_uri,
                                   String response_type,
                                   String response_mode,
                                   String scope,
                                   String code_challenge,
                                   String code_challenge_method,
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
                    this.state
            );
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
        model.addAttribute("scope", request.scope);
        model.addAttribute("state", request.state);
        model.addAttribute("principalName", authentication.getName());

        return "authorize";
    }

    @PostMapping
    public String approveAuthorization(@ModelAttribute AuthorizeRequest request) {
        // Custom logic to approve the authorization request.
        // Redirecting to the provided redirect URI after successful authorization
        String redirectUrl = request.redirect_uri + "?code=sample_auth_code&state=" + request.state;
        return "redirect:" + redirectUrl;
    }
}
