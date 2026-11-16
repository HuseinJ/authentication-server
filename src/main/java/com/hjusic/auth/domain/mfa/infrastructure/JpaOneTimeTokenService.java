package com.hjusic.auth.domain.mfa.infrastructure;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Database-backed {@link OneTimeTokenService} holding the "password ok, second factor pending"
 * state of a REST login between its two requests. Works across multiple instances, stores only
 * token hashes, and redeems each token at most once.
 */
@Component
@RequiredArgsConstructor
public class JpaOneTimeTokenService implements OneTimeTokenService {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final int TOKEN_BYTES = 32;

  private final MfaChallengeDatabaseRepository repository;
  private final Clock clock;

  @Override
  @Transactional
  public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
    Instant now = clock.instant();
    repository.deleteExpired(now);

    byte[] bytes = new byte[TOKEN_BYTES];
    RANDOM.nextBytes(bytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    Instant expiresAt = now.plus(request.getExpiresIn());

    repository.save(new MfaChallengeDatabaseEntity(hash(token), request.getUsername(), expiresAt));
    return new DefaultOneTimeToken(token, request.getUsername(), expiresAt);
  }

  @Override
  @Transactional
  public @Nullable OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
    String token = authenticationToken.getTokenValue();
    if (token == null || token.isBlank()) {
      return null;
    }
    String tokenHash = hash(token);
    var challenge = repository.findById(tokenHash);
    // The conditional delete decides who wins if the same token is redeemed concurrently.
    if (challenge.isEmpty() || repository.deleteByTokenHash(tokenHash) != 1) {
      return null;
    }
    if (clock.instant().isAfter(challenge.get().getExpiresAt())) {
      return null;
    }
    return new DefaultOneTimeToken(token, challenge.get().getUsername(),
        challenge.get().getExpiresAt());
  }

  private static String hash(String token) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(token.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }
}
