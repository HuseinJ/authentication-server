package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;

public class PasswordChangedEvent extends UserEvent{

  private final String newPassword;

  public PasswordChangedEvent(String eventId, Instant occurredOn,
      Username username, String newPassword) {
    super(eventId, occurredOn, username, null);
    this.newPassword = newPassword;
  }
}
