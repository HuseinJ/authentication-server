package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.Builder;
import lombok.Value;

import java.time.Duration;

@Value
@Builder
public class TokenSettings {
  @Builder.Default
  Duration accessTokenTimeToLive = Duration.ofHours(1);

  @Builder.Default
  Duration refreshTokenTimeToLive = Duration.ofDays(7);

  @Builder.Default
  Duration authorizationCodeTimeToLive = Duration.ofMinutes(5);

  @Builder.Default
  boolean reuseRefreshTokens = false;

  public static TokenSettings defaults() {
    return TokenSettings.builder().build();
  }
}

