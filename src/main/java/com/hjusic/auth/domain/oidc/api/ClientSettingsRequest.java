package com.hjusic.auth.domain.oidc.api;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientSettingsRequest {
  @Builder.Default
  private boolean requireAuthorizationConsent = true;
  @Builder.Default
  private boolean requireProofKey = true;
}
