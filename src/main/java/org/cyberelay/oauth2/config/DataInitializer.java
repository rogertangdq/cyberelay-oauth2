package org.cyberelay.oauth2.config;

import org.cyberelay.oauth2.dao.UserRepository;
import org.cyberelay.oauth2.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initializeDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            userRepository.save(new User("user", passwordEncoder.encode("password"), "USER"));
            userRepository.save(new User("admin", passwordEncoder.encode("admin"), "ADMIN"));
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
