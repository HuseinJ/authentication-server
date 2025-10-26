package com.hjusic.auth.notification.infrastructure;

import com.hjusic.auth.event.model.DomainEventPublisher;
import com.hjusic.auth.notification.model.Notification;
import com.hjusic.auth.notification.model.Notifications;
import com.hjusic.auth.notification.model.event.NotificationEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KafkaNotificationRepository implements Notifications {

  private final DomainEventPublisher publisher;
  private final KafkaTemplate<String, Notification> kafkaTemplate;
  private final String TOPIC_NAME = "notification";

  @Override
  public Notification publish(NotificationEvent notification) {
    kafkaTemplate.send(TOPIC_NAME, notification.getNotification());
    publisher.publish(notification);

    return notification.getNotification();
  }
}
