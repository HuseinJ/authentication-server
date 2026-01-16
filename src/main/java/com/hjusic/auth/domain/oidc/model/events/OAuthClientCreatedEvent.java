package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Value;

@Value
public class OAuthClientCreatedEvent {
    OAuthClient client;
    String plainTextSecret; // Only available in this event, should be shown to user once
}
