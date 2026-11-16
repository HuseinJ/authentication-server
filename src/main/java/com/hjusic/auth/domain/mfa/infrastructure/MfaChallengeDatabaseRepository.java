package com.hjusic.auth.domain.mfa.infrastructure;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MfaChallengeDatabaseRepository
    extends JpaRepository<MfaChallengeDatabaseEntity, String> {

  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("delete from MfaChallengeDatabaseEntity c where c.tokenHash = :tokenHash")
  int deleteByTokenHash(@Param("tokenHash") String tokenHash);

  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("delete from MfaChallengeDatabaseEntity c where c.expiresAt < :now")
  int deleteExpired(@Param("now") Instant now);
}
