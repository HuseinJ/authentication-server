package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Value;

import java.time.Duration;

@Value
@Builder
@NoArgsConstructor
@AllArgsConstructor
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
    return TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofSeconds(3600L))        // 1 hour
        .refreshTokenTimeToLive(Duration.ofSeconds(86400L))      // 24 hours
        .authorizationCodeTimeToLive(Duration.ofSeconds(300L))   // 5 minutes
        .reuseRefreshTokens(false)
        .build();
  }
}

