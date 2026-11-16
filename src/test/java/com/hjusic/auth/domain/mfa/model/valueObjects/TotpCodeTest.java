package com.hjusic.auth.domain.mfa.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.domain.mfa.model.MfaErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class TotpCodeTest {

  @Test
  @DisplayName("accepts six digits, tolerating spaces")
  void acceptsSixDigits() {
    assertThat(TotpCode.of("123456").get().getValue()).isEqualTo("123456");
    assertThat(TotpCode.of(" 123 456 ").get().getValue()).isEqualTo("123456");
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"12345", "1234567", "12a456", "abcdef"})
  @DisplayName("rejects anything that is not six digits")
  void rejectsInvalidFormats(String raw) {
    var result = TotpCode.of(raw);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getCode()).isEqualTo(MfaErrorCode.VALIDATION_FAILED);
  }
}
