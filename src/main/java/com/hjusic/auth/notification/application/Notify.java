package com.hjusic.auth.notification.application;

import com.hjusic.auth.notification.model.Notification;
import com.hjusic.auth.notification.model.NotificationError;
import com.hjusic.auth.notification.model.NotificationErrorCode;
import com.hjusic.auth.notification.model.NotificationType;
import com.hjusic.auth.notification.model.Notifications;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class Notify {

  private final Notifications notifications;

  public Either<NotificationError, Notification> sendNotifiaction(String recipient, String content) {

    if (StringUtils.isBlank(recipient)) {
      return Either.left(NotificationError.of("Recipient cannot be blank", NotificationErrorCode.RECIPIENT_INVALID));
    }

    if (StringUtils.isBlank(content)) {
      return Either.left(NotificationError.of("Content cannot be blank", NotificationErrorCode.BODY_EMPTY));
    }

    var notification = Notification.of(NotificationType.EMAIL, recipient, "noreply@mail.com", content);

    return Either.right(notifications.publish(notification.send()));
  }

}
