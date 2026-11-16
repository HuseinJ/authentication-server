package com.hjusic.auth.domain.mfa.model.event;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TotpEnrollmentStartedEvent extends TotpEvent {

  /** Never leaves the service: domain events are also published to Kafka. */
  @JsonIgnore
  private TotpSecret secret;

  private TotpEnrollmentStartedEvent(String username, TotpSecret secret) {
    super(username);
    this.secret = secret;
  }

  public static TotpEnrollmentStartedEvent of(String username, TotpSecret secret) {
    return new TotpEnrollmentStartedEvent(username, secret);
  }

  @Override
  public String getEventType() {
    return "TotpEnrollmentStartedEvent";
  }
}
