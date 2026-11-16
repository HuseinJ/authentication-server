package com.hjusic.auth.domain.mfa.model.event;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TotpCodeAcceptedEvent extends TotpEvent {

  private long timeStep;

  private TotpCodeAcceptedEvent(String username, long timeStep) {
    super(username);
    this.timeStep = timeStep;
  }

  public static TotpCodeAcceptedEvent of(String username, long timeStep) {
    return new TotpCodeAcceptedEvent(username, timeStep);
  }

  @Override
  public String getEventType() {
    return "TotpCodeAcceptedEvent";
  }
}
