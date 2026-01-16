package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import lombok.Value;

@Value
public class OAuthClientDeletedEvent {
    OAuthClientId id;
    ClientId clientId;
}
