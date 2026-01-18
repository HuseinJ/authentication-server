package com.hjusic.auth.domain.oidc.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ClientSettingsTest {

  @Test
  @DisplayName("Should create client settings with default values")
  void shouldCreateWithDefaults() {
    ClientSettings settings = ClientSettings.defaults();

    assertThat(settings.isRequireAuthorizationConsent()).isTrue();
    assertThat(settings.isRequireProofKey()).isFalse();
  }

  @Test
  @DisplayName("Should create client settings with custom values")
  void shouldCreateWithCustomValues() {
    ClientSettings settings = ClientSettings.builder()
        .requireAuthorizationConsent(false)
        .requireProofKey(true)
        .build();

    assertThat(settings.isRequireAuthorizationConsent()).isFalse();
    assertThat(settings.isRequireProofKey()).isTrue();
  }
}