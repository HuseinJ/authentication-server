package com.hjusic.auth.domain.user.model.event;


import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.ResetPasswordToken;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ResetPasswordProcessStartedEvent extends UserEvent {

  private ResetPasswordToken resetPasswordToken;

  public static ResetPasswordProcessStartedEvent of(Username username, Email email, ResetPasswordToken resetPasswordToken) {
    ResetPasswordProcessStartedEvent event = new ResetPasswordProcessStartedEvent();
    event.setEventId(java.util.UUID.randomUUID().toString());
    event.setOccurredOn(java.time.Instant.now());
    event.setUsername(username);
    event.setEmail(email);
    event.setResetPasswordToken(resetPasswordToken);
    return event;
  }

  @Override
  public String getEventType() {
    return "ResetPasswordProcessStartedEvent";
  }
}
