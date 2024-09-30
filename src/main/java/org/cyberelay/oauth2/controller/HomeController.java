package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.Optional;

@Controller
public class HomeController {

    @GetMapping(EndPoints.ROOT)
    public String home(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        var name = Optional.ofNullable(authentication).map(Principal::getName).orElse("Anonymous");
        var email = name + "@cyberelay.org";
        model.addAttribute("name", name);
        model.addAttribute("email", email);

        return "home"; // Render the home page
    }

    @GetMapping(EndPoints.LOGIN)
    public String login() {
        return "login"; // Render the custom login page
    }
}
