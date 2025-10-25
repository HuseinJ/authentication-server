package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;
import lombok.Getter;

@Getter
public class UsernameChangedEvent extends UserEvent {

  private final Username newUsername;

  private UsernameChangedEvent(String eventId, Instant occurredOn,
      Username username,
      Email email, Username newUsername) {
    super(eventId, occurredOn, username, email);
    this.newUsername = newUsername;
  }

  public static UsernameChangedEvent of(Username username, Username newUsername) {
    return new UsernameChangedEvent(
        java.util.UUID.randomUUID().toString(),
        Instant.now(),
        username,
        null,
        newUsername);
  }
}
