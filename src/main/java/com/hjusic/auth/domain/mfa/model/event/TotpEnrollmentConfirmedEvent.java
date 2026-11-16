package com.hjusic.auth.domain.mfa.model.event;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TotpEnrollmentConfirmedEvent extends TotpEvent {

  private long timeStep;

  private TotpEnrollmentConfirmedEvent(String username, long timeStep) {
    super(username);
    this.timeStep = timeStep;
  }

  public static TotpEnrollmentConfirmedEvent of(String username, long timeStep) {
    return new TotpEnrollmentConfirmedEvent(username, timeStep);
  }

  @Override
  public String getEventType() {
    return "TotpEnrollmentConfirmedEvent";
  }
}
