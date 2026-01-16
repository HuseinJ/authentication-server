package com.hjusic.auth.domain.client.model.event;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Value;

@Value
public class OAuthClientUpdatedEvent {
    OAuthClient client;
}
