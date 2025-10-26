package com.hjusic.auth.event.model;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public abstract class DomainEvent {
  private String eventId;
  private Instant occurredOn;
}
