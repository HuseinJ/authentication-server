package com.hjusic.auth.notification.model;

import com.hjusic.auth.notification.model.event.NotificationEvent;

public interface Notifications {
  Notification publish(NotificationEvent notification);
}
