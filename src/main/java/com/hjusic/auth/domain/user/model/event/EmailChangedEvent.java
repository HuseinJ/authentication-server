package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;
import lombok.Getter;

@Getter
public class EmailChangedEvent extends UserEvent{

  private final Email newEmail;

  public EmailChangedEvent(String eventId, Instant occurredOn,
      Username username, Email newEmail) {
    super(eventId, occurredOn, username, null);
    this.newEmail = newEmail;
  }
}
