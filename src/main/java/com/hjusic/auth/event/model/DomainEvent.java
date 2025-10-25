package com.hjusic.auth.event.model;

import java.time.Instant;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public abstract class DomainEvent {

  private final String eventId;
  private final Instant occurredOn;
}
