package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

@Value
@Builder
@Jacksonized
public class ClientSettings {

  @Builder.Default
  boolean requireAuthorizationConsent = true;

  @Builder.Default
  boolean requireProofKey = false;

  public static ClientSettings of(boolean requireAuthorizationConsent, boolean requireProofKey) {
    return ClientSettings.builder().requireAuthorizationConsent(requireAuthorizationConsent)
        .requireProofKey(requireProofKey).build();
  }

  public static ClientSettings defaults() {
    return ClientSettings.builder().build();
  }
}
