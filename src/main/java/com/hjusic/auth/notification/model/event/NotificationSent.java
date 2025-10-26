package com.hjusic.auth.notification.model.event;

import com.hjusic.auth.notification.model.Notification;
import java.time.Instant;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class NotificationSent extends NotificationEvent{

  private NotificationSent(String eventId, Instant occurredOn,
      Notification notification) {
    setNotification(notification);
    setEventId(eventId);
    setOccurredOn(occurredOn);
  }

  public static NotificationSent of(Notification notification) {
    return new NotificationSent(
        java.util.UUID.randomUUID().toString(),
        Instant.now(),
        notification);
  }
}
