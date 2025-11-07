package com.hjusic.auth.domain.user.infrastructure;

import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import com.hjusic.auth.notification.application.NotifyEmail;
import java.security.SecureRandom;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Log4j2
public class AdminInitializer{

  private final Users users;
  private final PasswordEncoder passwordEncoder;
  private final NotifyEmail notifyEmail;

  private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String DIGITS = "0123456789";
  private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  private static final String ALL_CHARS = UPPER + LOWER + DIGITS + SYMBOLS;
  private static final int DEFAULT_LENGTH = 64;

  @Value("${auth.admin.username}")
  private String username;

  @Value("${auth.admin.email}")
  private String email;

  @EventListener(ApplicationReadyEvent.class)
  public void initAdmin() {
    if (users.findByUsername(username).isRight()) {
      log.info("Admin user already exists, skipping initialization");
      return;
    }
    var gneratedPassword = generateSecurePassword();
    log.warn("Generated default password: {}", gneratedPassword);
    var passwordResult = Password.encode(gneratedPassword, passwordEncoder);
    if (passwordResult.isLeft()) {
      log.error("Failed to encode default password: {}", passwordResult.getLeft().getMessage());
      return;
    }

    users.trigger(
        UserCreatedEvent.of(
            Username.of(username).get(),
            Email.of(email).get(),
            passwordResult.get(),
            Set.of(RoleName.ROLE_ADMIN))
    );

    notifyEmail.sendNotifiaction(email, "Admin user created using username: " + username + " and email: " + email);

    log.info("Admin user created and notification sent");
  }

  private String generateSecurePassword() {
    SecureRandom random = new SecureRandom();
    StringBuilder sb = new StringBuilder(DEFAULT_LENGTH);

    // Ensure at least one character from each category
    sb.append(UPPER.charAt(random.nextInt(UPPER.length())));
    sb.append(LOWER.charAt(random.nextInt(LOWER.length())));
    sb.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
    sb.append(SYMBOLS.charAt(random.nextInt(SYMBOLS.length())));

    // Fill the rest of the password
    for (int i = 4; i < DEFAULT_LENGTH; i++) {
      sb.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
    }

    // Shuffle to avoid predictable order
    char[] passwordChars = sb.toString().toCharArray();
    for (int i = passwordChars.length - 1; i > 0; i--) {
      int j = random.nextInt(i + 1);
      char temp = passwordChars[i];
      passwordChars[i] = passwordChars[j];
      passwordChars[j] = temp;
    }

    return new String(passwordChars);
  }
}
