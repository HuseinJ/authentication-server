package com.hjusic.auth.domain.oidc.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import com.hjusic.auth.crypto.model.PasswordHasher;

class ClientSecretTest {

  @Nested
  @DisplayName("Client secret generation")
  class ClientSecretGenerationTests {

    @Test
    @DisplayName("Should generate a non-null secret")
    void shouldGenerateNonNullSecret() {
      var passwordHasher = mock(PasswordHasher.class);
      when(passwordHasher.hash(anyString())).thenReturn("hashed-secret");
      ClientSecret secret = ClientSecret.generate(passwordHasher);

      assertThat(secret).isNotNull();
      assertThat(secret.getPlainText()).isNotNull();
      assertThat(secret.getPlainText()).isNotBlank();
    }

    @Test
    @DisplayName("Should generate secret with sufficient length")
    void shouldGenerateSecretWithSufficientLength() {
      var passwordHasher = mock(PasswordHasher.class);
      when(passwordHasher.hash(anyString())).thenReturn("hashed-secret");
      ClientSecret secret = ClientSecret.generate(passwordHasher);

      // Base64 URL encoding of 32 bytes should be ~43 characters
      assertThat(secret.getPlainText().length()).isGreaterThanOrEqualTo(40);
    }

    @Test
    @DisplayName("Should generate unique secrets")
    void shouldGenerateUniqueSecrets() {
      var passwordHasher = mock(PasswordHasher.class);
      when(passwordHasher.hash(anyString())).thenReturn("hashed-secret");
      ClientSecret secret1 = ClientSecret.generate(passwordHasher);
      ClientSecret secret2 = ClientSecret.generate(passwordHasher);

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
      var passwordHasher = mock(PasswordHasher.class);
      when(passwordHasher.hash(anyString())).thenReturn("hashed-secret");
      ClientSecret originalSecret = ClientSecret.generate(passwordHasher);
      String encodedValue = "$2a$10$encodedSecretHash";

      ClientSecret withEncoded = originalSecret.withEncodedValue(encodedValue);

      assertThat(withEncoded.getEncodedValue()).isEqualTo(encodedValue);
      assertThat(withEncoded.getPlainText()).isEqualTo(originalSecret.getPlainText());
    }
  }
}