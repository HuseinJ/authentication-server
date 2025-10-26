package com.hjusic.auth.notification.model;

import com.hjusic.auth.notification.model.event.NotificationSent;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class Notification {
  private final UUID id;
  private final NotificationType type;
  private final String recipient;
  private final String sender;
  private final String content;

  public static Notification of(NotificationType type, String recipient, String sender, String content) {
    return new Notification(UUID.randomUUID(), type, recipient, sender, content);
  }

  public NotificationSent send() {
    return NotificationSent.of(this);
  }

}
