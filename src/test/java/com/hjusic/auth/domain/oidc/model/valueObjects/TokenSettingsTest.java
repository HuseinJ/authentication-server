package com.hjusic.auth.domain.oidc.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

class TokenSettingsTest {

  @Test
  @DisplayName("Should create token settings with default values")
  void shouldCreateWithDefaults() {
    TokenSettings settings = TokenSettings.defaults();

    assertThat(settings.getAccessTokenTimeToLive()).isEqualTo(Duration.ofHours(1));
    assertThat(settings.getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(1));
    assertThat(settings.getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofMinutes(5));
    assertThat(settings.isReuseRefreshTokens()).isFalse();
  }

  @Test
  @DisplayName("Should create token settings with custom values")
  void shouldCreateWithCustomValues() {
    TokenSettings settings = TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(30))
        .refreshTokenTimeToLive(Duration.ofDays(30))
        .authorizationCodeTimeToLive(Duration.ofMinutes(10))
        .reuseRefreshTokens(true)
        .build();

    assertThat(settings.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(30));
    assertThat(settings.getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(30));
    assertThat(settings.getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofMinutes(10));
    assertThat(settings.isReuseRefreshTokens()).isTrue();
  }
}