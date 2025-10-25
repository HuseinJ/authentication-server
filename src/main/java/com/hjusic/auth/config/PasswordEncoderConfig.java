package com.hjusic.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class PasswordEncoderConfig {

  @Bean
  public PasswordEncoder passwordEncoder() {
    int saltLength = 16;        // Salt length in bytes
    int hashLength = 32;        // Hash length in bytes
    int parallelism = 1;        // Number of parallel threads
    int memory = 65536;         // Memory cost in KB (64 MB)
    int iterations = 3;         // Number of iterations

    Argon2PasswordEncoder argon2Encoder = new Argon2PasswordEncoder(
        saltLength,
        hashLength,
        parallelism,
        memory,
        iterations
    );

    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("argon2", argon2Encoder);
    encoders.put("bcrypt", new BCryptPasswordEncoder(12));
    encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
    encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());

    DelegatingPasswordEncoder delegatingEncoder =
        new DelegatingPasswordEncoder("argon2", encoders);

    return delegatingEncoder;
  }
}
