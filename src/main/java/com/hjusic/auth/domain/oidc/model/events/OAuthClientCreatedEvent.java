package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientCreatedEvent extends OidcClientEvent {
    String plainTextSecret; // Only available in this event, should be shown to user once

    public static OAuthClientCreatedEvent of(OAuthClient client, String plainTextSecret) {
        var oAuthClient = new OAuthClientCreatedEvent();
        oAuthClient.setClient(client);
        oAuthClient.setPlainTextSecret(plainTextSecret);

        return oAuthClient;
    }
}
