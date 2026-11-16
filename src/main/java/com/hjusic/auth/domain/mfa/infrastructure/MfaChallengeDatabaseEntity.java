package com.hjusic.auth.domain.mfa.infrastructure;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** A pending REST login that passed the password check and still needs its second factor. */
@Entity
@Table(name = "mfa_challenges")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MfaChallengeDatabaseEntity {

  /** SHA-256 of the token handed to the client; the raw token is never stored. */
  @Id
  @Column(name = "token_hash", length = 64)
  private String tokenHash;

  @Column(nullable = false)
  private String username;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;
}
