package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class UserDeletedEvent extends UserEvent {
  
  public static UserDeletedEvent of(Username username) {
    UserDeletedEvent event = new UserDeletedEvent();
    event.setEventId(java.util.UUID.randomUUID().toString());
    event.setOccurredOn(Instant.now());
    event.setUsername(username);
    return event;
  }

  @Override
  public String getEventType() {
    return "UserDeletedEvent";
  }
}
