package org.cyberelay.oauth2.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Entity
@Table(name = "oauth2_client")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column
    private String clientId;

    @Column
    private String clientSecret;

    @Transient
    private String decodedClientSecret;

    @Column
    private String redirectUris;

    @Column
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

    public String getRedirectUris() {
        return redirectUris;
    }

    public String getScopes() {
        return scopes;
    }

    // Convert this object into spring RegisteredClient object
    public RegisteredClient toRegisteredClient() {
        RegisteredClient.Builder builder = RegisteredClient
                .withId(this.id)
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
        entity.redirectUris = String.join(",", registeredClient.getRedirectUris());
        entity.scopes = String.join(",", registeredClient.getScopes());
        return entity;
    }

    public static Builder builder() {
        return builder(null);
    }

    public static Builder builder(Client template) {
        var builder = new Builder();
        if (template != null) {
            builder.clientSecret(template.clientSecret)
                    .clientId(template.clientId)
                    .redirectUris(template.redirectUris)
                    .scopes(template.scopes)
                    .decodedClientSecret(template.decodedClientSecret);
        }

        return builder;
    }

    public static class Builder {
        private Client template;
        private Builder() {
            this.template = new Client();
        }

        public Builder clientId(String clientId) {
            template.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            template.clientSecret = clientSecret;
            return this;
        }

        public Builder scopes(String... scope) {
            template.scopes = String.join(",", scope);
            return this;
        }

        public Builder redirectUris(String... redirectUri) {
            template.redirectUris = String.join(",", redirectUri);
            return this;
        }

        public Builder decodedClientSecret(String decodedSecret) {
            template.decodedClientSecret = decodedSecret;
            return this;
        }

        public Client build() {
            var newClient = new Client();
            newClient.clientId = template.clientId;
            newClient.clientSecret = template.clientSecret;
            newClient.redirectUris = template.redirectUris;
            newClient.scopes = template.scopes;
            newClient.decodedClientSecret = template.decodedClientSecret;

            return newClient;
        }
    }
}
