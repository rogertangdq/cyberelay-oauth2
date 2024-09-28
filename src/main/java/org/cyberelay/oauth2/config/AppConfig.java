package org.cyberelay.oauth2.config;

import org.cyberelay.oauth2.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import org.cyberelay.oauth2.dao.UserRepository;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

@Configuration
@EnableWebSecurity
public class AppConfig {
    private static final String[] PUBLIC_ENDPOINTS = {
            EndPoints.LOGIN,
            EndPoints.JWKS_URI,
            EndPoints.TOKEN,
            EndPoints.DISCOVERY_URI,
            "/css/**",
            "/js/**",
            "/h2-console/**"
    };

    private final UserRepository userRepository;

    public AppConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage(EndPoints.LOGIN)
                        .defaultSuccessUrl(EndPoints.AUTHORIZATION, true) // return to authorization after login
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl(EndPoints.LOGIN + "?logout").permitAll()
                )
                .csrf(AbstractHttpConfigurer::disable) // Enable access to H2 console
                .headers(headersConfigurer -> headersConfigurer
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            var user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            return org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password(user.getPassword())
                    .roles(user.getRole())
                    .build();
        };
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        // Combine them to form the OAuth2TokenGenerator
        return new OAuth2AccessTokenGenerator();
    }

    @Bean
    public KeyPair keyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")); // P-256 curve
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    @Bean
    public CommandLineRunner initializeDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        // Pre-populate built-in user accounts for dev use
        // TODO make this bean for dev only
        return args -> {
            userRepository.save(new User("user", passwordEncoder.encode("password"), "USER"));
            userRepository.save(new User("admin", passwordEncoder.encode("admin"), "ADMIN"));
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ECPrivateKey ecPrivateKey(KeyPair keyPair) {
        return (ECPrivateKey) keyPair.getPrivate();
    }

    @Bean
    public ECPublicKey ecPublicKey(KeyPair keyPair) {
        return (ECPublicKey) keyPair.getPublic();
    }
}
