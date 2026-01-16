package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Value;

@Value
public class OAuthClientSecretRegeneratedEvent {
    OAuthClient client;
    String plainTextSecret;
}
