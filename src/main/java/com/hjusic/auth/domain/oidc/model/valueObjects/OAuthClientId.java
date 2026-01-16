package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.util.UUID;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuthClientId {
  UUID value;

  public static OAuthClientId generate() {
    return new OAuthClientId(UUID.randomUUID());
  }

  public static OAuthClientId of(UUID id) {
    return new OAuthClientId(id);
  }

  public static OAuthClientId of(String id) {
    return new OAuthClientId(UUID.fromString(id));
  }
}

