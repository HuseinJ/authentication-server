package com.hjusic.auth.notification.model;

import com.hjusic.auth.notification.model.event.NotificationSent;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Data
public class Notification {
  private final UUID id;
  private final NotificationType type;
  private final String recipient;
  private final String sender;
  private final String subject;
  private final String content;

  public static Notification of(NotificationType type, String recipient, String sender, String subject, String content) {
    return new Notification(UUID.randomUUID(), type, recipient, sender, subject, content);
  }

  public NotificationSent send() {
    return NotificationSent.of(this);
  }

}
