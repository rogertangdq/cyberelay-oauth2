package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.cyberelay.oauth2.dao.ClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping(EndPoints.AUTHORIZATION)
public class AuthorizationController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationController.class);

    private final ClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    public AuthorizationController(ClientRepository registeredClientRepository,
                                   OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    public record AuthorizeRequest(String client_id,
                                   String redirect_uri,
                                   String response_type,
                                   String response_mode,
                                   String scope,
                                   String code_challenge,
                                   String code_challenge_method,
                                   String state) {
    }

    @GetMapping
    public String authorize(@ModelAttribute AuthorizeRequest request,
                            Model model,
                            @AuthenticationPrincipal Authentication principal) {
        var client = registeredClientRepository.findByClientId(request.client_id);

        if (client.isEmpty()) {
            LOG.warn("Authorization request has no client_id");
            //throw new IllegalArgumentException("Invalid client_id");
        }

        model.addAttribute("clientId", request.client_id);
        model.addAttribute("redirectUri", request.redirect_uri);
        model.addAttribute("responseType", request.response_type);
        model.addAttribute("scope", request.scope);
        model.addAttribute("state", request.state);
        model.addAttribute("principalName", principal == null ? null : principal.getName());

        return "authorize";
    }

    @PostMapping
    public String approveAuthorization(@RequestBody AuthorizeRequest request, Principal principal) {
        // Custom logic to approve the authorization request.
        // Redirecting to the provided redirect URI after successful authorization
        String redirectUrl = request.redirect_uri + "?code=sample_auth_code&state=" + request.state;
        return "redirect:" + redirectUrl;
    }
}
