package org.cyberelay.oauth2.controller;

import org.cyberelay.oauth2.config.EndPoints;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping(EndPoints.ROOT)
    public String home() {
        return "home"; // Render the home page
    }

    @GetMapping(EndPoints.LOGIN)
    public String login() {
        return "login"; // Render the custom login page
    }
}
