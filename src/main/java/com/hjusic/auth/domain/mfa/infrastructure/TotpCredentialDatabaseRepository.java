package com.hjusic.auth.domain.mfa.infrastructure;

import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TotpCredentialDatabaseRepository
    extends JpaRepository<TotpCredentialDatabaseEntity, Long> {

  Optional<TotpCredentialDatabaseEntity> findByUserUsername(String username);

  boolean existsByUserUsernameAndConfirmedTrue(String username);

  /**
   * Burns a time step atomically: the row only changes if no code from this step (or a later one)
   * was accepted in the meantime, which closes the replay race between concurrent logins.
   */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("""
      update TotpCredentialDatabaseEntity t
         set t.lastUsedTimeStep = :step, t.failedAttempts = 0, t.lockedUntil = null,
             t.confirmed = true, t.updatedAt = :now
       where t.user.id in (select u.id from UserDatabaseEntity u where u.username = :username)
         and (t.lastUsedTimeStep is null or t.lastUsedTimeStep < :step)
      """)
  int markTimeStepUsed(@Param("username") String username, @Param("step") long step,
      @Param("now") Instant now);

  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query("""
      delete from TotpCredentialDatabaseEntity t
       where t.user.id in (select u.id from UserDatabaseEntity u where u.username = :username)
      """)
  int deleteByUsername(@Param("username") String username);
}
