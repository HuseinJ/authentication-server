package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class ClientSettings {
  @Builder.Default
  boolean requireAuthorizationConsent = true;

  @Builder.Default
  boolean requireProofKey = false; // PKCE

  public static ClientSettings defaults() {
    return ClientSettings.builder().build();
  }
}
