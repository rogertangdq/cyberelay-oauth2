package org.cyberelay.oauth2.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Entity
@Table(name = "oauth2_client")
public class Client {

    @Id
    private String id;

    private String clientId;
    private String clientSecret;
    private String clientAuthenticationMethods;
    private String authorizationGrantTypes;
    private String redirectUris;
    private String scopes;

    public String getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    public String getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    public String getRedirectUris() {
        return redirectUris;
    }

    public String getScopes() {
        return scopes;
    }

    // Map the entity fields to the RegisteredClient object
    public RegisteredClient toRegisteredClient() {
        RegisteredClient.Builder builder = RegisteredClient.withId(this.id)
                .clientId(this.clientId)
                .clientSecret(this.clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);

        if (redirectUris != null && !redirectUris.isEmpty()) {
            for (String uri : redirectUris.split(",")) {
                builder.redirectUri(uri);
            }
        }

        if (scopes != null && !scopes.isEmpty()) {
            for (String scope : scopes.split(",")) {
                builder.scope(scope);
            }
        }

        return builder.build();
    }

    public static Client fromRegisteredClient(RegisteredClient registeredClient) {
        Client entity = new Client();
        entity.id = registeredClient.getId();
        entity.clientId = registeredClient.getClientId();
        entity.clientSecret = registeredClient.getClientSecret();
        entity.clientAuthenticationMethods = String.join(",", registeredClient.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).toArray(String[]::new));
        entity.authorizationGrantTypes = String.join(",", registeredClient.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).toArray(String[]::new));
        entity.redirectUris = String.join(",", registeredClient.getRedirectUris());
        entity.scopes = String.join(",", registeredClient.getScopes());
        return entity;
    }

    // Getters and Setters
}
