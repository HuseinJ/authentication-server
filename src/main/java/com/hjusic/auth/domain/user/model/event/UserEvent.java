package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import com.hjusic.auth.event.model.DomainEvent;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class UserEvent extends DomainEvent {
  private Username username;
  private Email email;

  public abstract String getEventType();
}
