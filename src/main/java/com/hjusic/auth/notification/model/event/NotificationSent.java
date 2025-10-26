package com.hjusic.auth.notification.model.event;

import com.hjusic.auth.notification.model.Notification;
import java.time.Instant;

public class NotificationSent extends NotificationEvent{

  private NotificationSent(String eventId, Instant occurredOn,
      Notification notification) {
    super(eventId, occurredOn, notification);
  }

  public static NotificationSent of(Notification notification) {
    return new NotificationSent(
        java.util.UUID.randomUUID().toString(),
        Instant.now(),
        notification);
  }
}
