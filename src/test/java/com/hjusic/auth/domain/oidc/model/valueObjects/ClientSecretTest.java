package com.hjusic.auth.domain.oidc.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class ClientSecretTest {

  @Nested
  @DisplayName("Client secret generation")
  class ClientSecretGenerationTests {

    @Test
    @DisplayName("Should generate a non-null secret")
    void shouldGenerateNonNullSecret() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      ClientSecret secret = ClientSecret.generate(passwordEncoder);

      assertThat(secret).isNotNull();
      assertThat(secret.getPlainText()).isNotNull();
      assertThat(secret.getPlainText()).isNotBlank();
    }

    @Test
    @DisplayName("Should generate secret with sufficient length")
    void shouldGenerateSecretWithSufficientLength() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      ClientSecret secret = ClientSecret.generate(passwordEncoder);

      // Base64 URL encoding of 32 bytes should be ~43 characters
      assertThat(secret.getPlainText().length()).isGreaterThanOrEqualTo(40);
    }

    @Test
    @DisplayName("Should generate unique secrets")
    void shouldGenerateUniqueSecrets() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      ClientSecret secret1 = ClientSecret.generate(passwordEncoder);
      ClientSecret secret2 = ClientSecret.generate(passwordEncoder);

      assertThat(secret1.getPlainText()).isNotEqualTo(secret2.getPlainText());
    }
  }

  @Nested
  @DisplayName("Client secret from encoded")
  class ClientSecretFromEncodedTests {

    @Test
    @DisplayName("Should create secret from encoded value")
    void shouldCreateFromEncodedValue() {
      String encodedValue = "$2a$10$encodedSecretHash";
      ClientSecret secret = ClientSecret.fromEncoded(encodedValue);

      assertThat(secret.getEncodedValue()).isEqualTo(encodedValue);
      assertThat(secret.getPlainText()).isNull();
    }

    @Test
    @DisplayName("Should add encoded value to existing secret")
    void shouldAddEncodedValue() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      ClientSecret originalSecret = ClientSecret.generate(passwordEncoder);
      String encodedValue = "$2a$10$encodedSecretHash";

      ClientSecret withEncoded = originalSecret.withEncodedValue(encodedValue);

      assertThat(withEncoded.getEncodedValue()).isEqualTo(encodedValue);
      assertThat(withEncoded.getPlainText()).isEqualTo(originalSecret.getPlainText());
    }
  }
}