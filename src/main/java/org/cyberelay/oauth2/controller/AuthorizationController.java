package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.cyberelay.oauth2.dao.ClientRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping(EndPoints.AUTHORIZATION)
public class AuthorizationController {

    private final ClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    public AuthorizationController(ClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    @GetMapping
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType,
            @RequestParam("scope") String scope,
            @RequestParam("state") String state,
            Model model,
            @AuthenticationPrincipal Authentication principal) {
        var client = registeredClientRepository.findByClientId(clientId);

        if (client.isEmpty()) {
            throw new IllegalArgumentException("Invalid client_id");
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("responseType", responseType);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state);
        model.addAttribute("principalName", principal.getName());

        return "authorize";
    }

    @PostMapping
    public String approveAuthorization(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("scope") String scope,
            @RequestParam("state") String state,
            Principal principal) {

        // Custom logic to approve the authorization request.
        // Redirecting to the provided redirect URI after successful authorization

        String redirectUrl = redirectUri + "?code=sample_auth_code&state=" + state;
        return "redirect:" + redirectUrl;
    }
}
