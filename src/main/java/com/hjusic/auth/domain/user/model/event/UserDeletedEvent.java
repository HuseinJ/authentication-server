package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;

public class UserDeletedEvent extends UserEvent {

  private UserDeletedEvent(String eventId, Instant occurredOn,
      Username username,
      Email email) {
    super(eventId, occurredOn, username, email);
  }

  public static UserDeletedEvent of(Username username) {
    return new UserDeletedEvent(
        java.util.UUID.randomUUID().toString(),
        Instant.now(),
        username,
        null
    );
  }
}
