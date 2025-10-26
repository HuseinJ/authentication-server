package com.hjusic.auth.notification.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class NotificationError {

  String message;
  NotificationErrorCode code;

  public static NotificationError of(String message, NotificationErrorCode code) {
    return new NotificationError(message, code);
  }

}
