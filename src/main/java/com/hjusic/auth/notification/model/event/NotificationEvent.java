package com.hjusic.auth.notification.model.event;

import com.hjusic.auth.event.model.DomainEvent;
import com.hjusic.auth.notification.model.Notification;
import java.time.Instant;
import lombok.Getter;

@Getter
public abstract class NotificationEvent extends DomainEvent {

  private final Notification notification;

  public NotificationEvent(String eventId, Instant occurredOn, Notification notification) {
    super(eventId, occurredOn);
    this.notification = notification;
  }
}
