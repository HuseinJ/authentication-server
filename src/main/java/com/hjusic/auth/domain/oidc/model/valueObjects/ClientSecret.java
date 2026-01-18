package com.hjusic.auth.domain.oidc.model.valueObjects;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientSecret {
  String encodedValue;
  String plainText;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static ClientSecret generate(PasswordEncoder passwordEncoder) {
    byte[] secretBytes = new byte[32];
    SECURE_RANDOM.nextBytes(secretBytes);
    String plainText = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
    String encodedValue = passwordEncoder.encode(plainText);
    return new ClientSecret(encodedValue, plainText);
  }

  public static ClientSecret fromEncoded(String encodedValue) {
    return new ClientSecret(encodedValue, null);
  }

  public ClientSecret withEncodedValue(String encodedValue) {
    return new ClientSecret(encodedValue, this.plainText);
  }
}


