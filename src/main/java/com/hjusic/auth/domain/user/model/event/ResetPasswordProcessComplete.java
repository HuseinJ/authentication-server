package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.ResetPasswordToken;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ResetPasswordProcessComplete extends UserEvent {

  private Password password;

  public static ResetPasswordProcessComplete of(Username username, Password password) {
    ResetPasswordProcessComplete event = new ResetPasswordProcessComplete();
    event.setEventId(java.util.UUID.randomUUID().toString());
    event.setOccurredOn(java.time.Instant.now());
    event.setUsername(username);
    event.setPassword(password);
    return event;
  }

  @Override
  public String getEventType() {
    return "ResetPasswordProcessComplete";
  }
}
