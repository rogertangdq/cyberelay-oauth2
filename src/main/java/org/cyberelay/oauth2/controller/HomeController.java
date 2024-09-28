package org.cyberelay.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home"; // Render the home page
    }

    @GetMapping("/login")
    public String login() {
        return "login"; // Render the custom login page
    }
}
