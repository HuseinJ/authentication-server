package com.hjusic.auth.domain.oidc.api;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenSettingsRequest {

  private int accessTokenTimeToLiveSeconds;
  private int refreshTokenTimeToLiveSeconds;
  private int authorizationCodeTimeToLiveSeconds;
  @Builder.Default
  private boolean reuseRefreshTokens = false;

}
