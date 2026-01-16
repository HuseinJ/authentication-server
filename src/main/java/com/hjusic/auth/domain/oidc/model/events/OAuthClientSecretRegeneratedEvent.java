package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper=false)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientSecretRegeneratedEvent extends OidcClientEvent {
    String plainTextSecret;

    public static OAuthClientSecretRegeneratedEvent of(OAuthClient client, String plainTextSecret) {
        var event = new OAuthClientSecretRegeneratedEvent();
        event.setClient(client);
        event.setPlainTextSecret(plainTextSecret);
        return event;
    }
}
