package com.hjusic.auth.domain.mfa.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TotpSecretTest {

  @Test
  @DisplayName("Base32 encoding follows RFC 4648 (without padding)")
  void base32MatchesRfc4648() {
    TotpSecret secret = TotpSecret.of("foobarbazq".getBytes(StandardCharsets.US_ASCII));

    assertThat(secret.toBase32()).isEqualTo("MZXW6YTBOJRGC6TR");
  }

  @Test
  @DisplayName("Base32 round-trips, ignoring padding, spaces and case")
  void base32RoundTrip() {
    TotpSecret secret = TotpSecret.generate();

    assertThat(TotpSecret.fromBase32(secret.toBase32())).isEqualTo(secret);
    assertThat(TotpSecret.fromBase32(secret.toBase32().toLowerCase() + "====")).isEqualTo(secret);
  }

  @Test
  @DisplayName("generated secrets are 160 bits and unique")
  void generatedSecrets() {
    assertThat(TotpSecret.generate().getValue()).hasSize(20);
    assertThat(TotpSecret.generate()).isNotEqualTo(TotpSecret.generate());
  }

  @Test
  @DisplayName("rejects secrets shorter than 80 bits")
  void rejectsShortSecrets() {
    assertThatThrownBy(() -> TotpSecret.of(new byte[9]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("builds an otpauth URI authenticator apps understand")
  void otpAuthUri() {
    TotpSecret secret = TotpSecret.of("foobarbazq".getBytes(StandardCharsets.US_ASCII));

    assertThat(secret.toOtpAuthUri("My Issuer", "alice"))
        .isEqualTo("otpauth://totp/My%20Issuer:alice?secret=MZXW6YTBOJRGC6TR&issuer=My%20Issuer"
            + "&algorithm=SHA1&digits=6&period=30");
  }

  @Test
  @DisplayName("never prints the secret")
  void toStringIsMasked() {
    assertThat(TotpSecret.generate().toString()).doesNotContainPattern("[A-Z2-7]{16}");
  }
}
