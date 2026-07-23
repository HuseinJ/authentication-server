package com.hjusic.auth.crypto.infrastructure;

import com.hjusic.auth.crypto.model.PasswordHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter implementing the {@link PasswordHasher} port with Spring Security's
 * {@link PasswordEncoder} (configured as a delegating Argon2 encoder in {@code PasswordEncoderConfig}).
 */
@Component
@RequiredArgsConstructor
public class SpringPasswordHasher implements PasswordHasher {

  private final PasswordEncoder passwordEncoder;

  @Override
  public String hash(String plaintext) {
    return passwordEncoder.encode(plaintext);
  }

  @Override
  public boolean matches(String plaintext, String hashedValue) {
    return passwordEncoder.matches(plaintext, hashedValue);
  }
}
