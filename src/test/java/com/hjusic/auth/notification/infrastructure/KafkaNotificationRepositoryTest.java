package com.hjusic.auth.notification.infrastructure;

import com.hjusic.auth.event.model.DomainEventPublisher;
import com.hjusic.auth.notification.model.Notification;
import com.hjusic.auth.notification.model.NotificationType;
import com.hjusic.auth.notification.model.event.NotificationSent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("KafkaNotificationRepository Tests")
class KafkaNotificationRepositoryTest {

  @Mock
  private DomainEventPublisher publisher;

  @Mock
  private KafkaTemplate<String, Notification> kafkaTemplate;

  @InjectMocks
  private KafkaNotificationRepository repository;

  @Captor
  private ArgumentCaptor<Notification> notificationCaptor;

  @Captor
  private ArgumentCaptor<NotificationSent> eventCaptor;

  private static final String TOPIC_NAME = "notification";
  private static final String RECIPIENT = "test@example.com";
  private static final String SENDER = "noreply@mail.com";
  private static final String CONTENT = "Test notification content";

  private Notification testNotification;
  private NotificationSent testEvent;

  @BeforeEach
  void setUp() {
    testNotification = Notification.of(
        NotificationType.EMAIL,
        RECIPIENT,
        SENDER,
        CONTENT
    );
    testEvent = testNotification.send();
  }

  @Test
  @DisplayName("should send notification to Kafka topic")
  void shouldSendNotificationToKafkaTopic() {
    repository.publish(testEvent);

    verify(kafkaTemplate).send(eq(TOPIC_NAME), notificationCaptor.capture());
    Notification capturedNotification = notificationCaptor.getValue();

    assertThat(capturedNotification).isEqualTo(testNotification);
  }

  @Test
  @DisplayName("should publish domain event")
  void shouldPublishDomainEvent() {
    repository.publish(testEvent);

    verify(publisher).publish(eventCaptor.capture());
    NotificationSent capturedEvent = eventCaptor.getValue();

    assertThat(capturedEvent).isEqualTo(testEvent);
  }

  @Test
  @DisplayName("should return the notification from the event")
  void shouldReturnNotificationFromEvent() {
    Notification result = repository.publish(testEvent);

    assertThat(result).isEqualTo(testNotification);
  }

  @Test
  @DisplayName("should send to Kafka before publishing domain event")
  void shouldSendToKafkaBeforePublishingDomainEvent() {
    repository.publish(testEvent);

    var inOrder = org.mockito.Mockito.inOrder(kafkaTemplate, publisher);
    inOrder.verify(kafkaTemplate).send(eq(TOPIC_NAME), notificationCaptor.capture());
    inOrder.verify(publisher).publish(eventCaptor.capture());
  }

  @Test
  @DisplayName("should handle notification with special characters")
  void shouldHandleNotificationWithSpecialCharacters() {
    String specialContent = "Test <html>content</html> with émojis 🎉 and newlines\n\ttabs";
    Notification specialNotification = Notification.of(
        NotificationType.EMAIL,
        RECIPIENT,
        SENDER,
        specialContent
    );
    NotificationSent specialEvent = specialNotification.send();

    Notification result = repository.publish(specialEvent);

    verify(kafkaTemplate).send(eq(TOPIC_NAME), eq(specialNotification));
    verify(publisher).publish(eq(specialEvent));
    assertThat(result).isEqualTo(specialNotification);
  }

  @Test
  @DisplayName("should handle notification with very long content")
  void shouldHandleNotificationWithVeryLongContent() {
    String longContent = "content ".repeat(10000);
    Notification longNotification = Notification.of(
        NotificationType.EMAIL,
        RECIPIENT,
        SENDER,
        longContent
    );
    NotificationSent longEvent = longNotification.send();

    Notification result = repository.publish(longEvent);

    verify(kafkaTemplate).send(eq(TOPIC_NAME), eq(longNotification));
    verify(publisher).publish(eq(longEvent));
    assertThat(result).isEqualTo(longNotification);
  }
}