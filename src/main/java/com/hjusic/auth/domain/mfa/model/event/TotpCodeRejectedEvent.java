package com.hjusic.auth.domain.mfa.model.event;

import java.time.Instant;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TotpCodeRejectedEvent extends TotpEvent {

  /** Consecutive failures after this rejection (reset to 0 once a lock is applied). */
  private int failedAttempts;

  /** Set when this rejection triggered a lockout, otherwise {@code null}. */
  private Instant lockedUntil;

  private TotpCodeRejectedEvent(String username, int failedAttempts, Instant lockedUntil) {
    super(username);
    this.failedAttempts = failedAttempts;
    this.lockedUntil = lockedUntil;
  }

  public static TotpCodeRejectedEvent of(String username, int failedAttempts, Instant lockedUntil) {
    return new TotpCodeRejectedEvent(username, failedAttempts, lockedUntil);
  }

  @Override
  public String getEventType() {
    return "TotpCodeRejectedEvent";
  }
}
