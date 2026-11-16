package com.hjusic.auth.domain.mfa.model.event;

import com.hjusic.auth.event.model.DomainEvent;
import java.time.Instant;
import java.util.UUID;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class TotpEvent extends DomainEvent {

  private String username;

  protected TotpEvent(String username) {
    super(UUID.randomUUID().toString(), Instant.now());
    this.username = username;
  }

  public abstract String getEventType();
}
