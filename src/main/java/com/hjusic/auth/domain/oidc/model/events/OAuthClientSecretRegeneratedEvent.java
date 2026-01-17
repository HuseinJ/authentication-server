package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSecret;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper=false)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientSecretRegeneratedEvent extends OidcClientEvent {
    ClientSecret newClientSecret;

    public static OAuthClientSecretRegeneratedEvent of(OidcClient client, ClientSecret newClientSecret) {
        var event = new OAuthClientSecretRegeneratedEvent();
        event.setClient(client);
        event.setNewClientSecret(newClientSecret);
        return event;
    }
}
