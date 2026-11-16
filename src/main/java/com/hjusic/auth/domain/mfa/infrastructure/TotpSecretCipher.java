package com.hjusic.auth.domain.mfa.infrastructure;

import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

/**
 * Encrypts TOTP secrets at rest. Unlike passwords they cannot be hashed, because verifying a code
 * needs the raw secret. Uses Spring Security's {@link Encryptors#delux} (AES-256-GCM with a
 * PBKDF2-derived key and a random IV per value).
 */
@Component
class TotpSecretCipher {

  private final TextEncryptor encryptor;

  TotpSecretCipher(
      @Value("${auth.mfa.totp.encryption-password}") String password,
      @Value("${auth.mfa.totp.encryption-salt}") String hexSalt) {
    this.encryptor = Encryptors.delux(password, hexSalt);
  }

  String encrypt(TotpSecret secret) {
    return encryptor.encrypt(Base64.getEncoder().encodeToString(secret.getValue()));
  }

  TotpSecret decrypt(String encrypted) {
    return TotpSecret.of(Base64.getDecoder().decode(encryptor.decrypt(encrypted)));
  }
}
