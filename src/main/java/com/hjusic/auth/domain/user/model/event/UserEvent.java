package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import com.hjusic.auth.event.model.DomainEvent;
import java.time.Instant;
import lombok.Getter;

@Getter
public abstract class UserEvent extends DomainEvent {

  Username username;
  Email email;

  public UserEvent(String eventId, Instant occurredOn, Username username, Email email) {
    super(eventId, occurredOn);
    this.username = username;
    this.email = email;
  }
}
