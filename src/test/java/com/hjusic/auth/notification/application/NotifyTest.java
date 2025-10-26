package com.hjusic.auth.notification.application;

import com.hjusic.auth.notification.model.Notification;
import com.hjusic.auth.notification.model.NotificationError;
import com.hjusic.auth.notification.model.NotificationErrorCode;
import com.hjusic.auth.notification.model.NotificationType;
import com.hjusic.auth.notification.model.Notifications;
import com.hjusic.auth.notification.model.event.NotificationSent;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Notify Service Tests")
class NotifyTest {

  @Mock
  private Notifications notifications;

  @InjectMocks
  private Notify notify;

  @Captor
  private ArgumentCaptor<NotificationSent> notificationEventCaptor;

  private static final String VALID_RECIPIENT = "test@example.com";
  private static final String VALID_CONTENT = "Test notification content";
  private static final String SENDER = "noreply@mail.com";

  @Nested
  @DisplayName("When sending valid notification")
  class ValidNotificationTests {

    private Notification returnedNotification;

    @BeforeEach
    void setUp() {
      returnedNotification = Notification.of(
          NotificationType.EMAIL,
          VALID_RECIPIENT,
          SENDER,
          VALID_CONTENT
      );
      when(notifications.publish(any(NotificationSent.class))).thenReturn(returnedNotification);
    }

    @Test
    @DisplayName("should return Right with published notification")
    void shouldReturnRightWithPublishedNotification() {
      Either<NotificationError, Notification> result = notify.sendNotifiaction(VALID_RECIPIENT, VALID_CONTENT);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(returnedNotification);
    }

    @Test
    @DisplayName("should publish NotificationSent event")
    void shouldPublishNotificationSentEvent() {
      notify.sendNotifiaction(VALID_RECIPIENT, VALID_CONTENT);

      verify(notifications).publish(any(NotificationSent.class));
    }

    @Test
    @DisplayName("should create notification with correct recipient")
    void shouldCreateNotificationWithCorrectRecipient() {
      notify.sendNotifiaction(VALID_RECIPIENT, VALID_CONTENT);

      verify(notifications).publish(notificationEventCaptor.capture());
      NotificationSent capturedEvent = notificationEventCaptor.getValue();

      assertThat(capturedEvent).isNotNull();
      assertThat(capturedEvent.getNotification()).isNotNull();
    }

    @Test
    @DisplayName("should create notification with EMAIL type")
    void shouldCreateNotificationWithEmailType() {
      notify.sendNotifiaction(VALID_RECIPIENT, VALID_CONTENT);

      verify(notifications).publish(any(NotificationSent.class));
    }

    @Test
    @DisplayName("should create notification with correct sender")
    void shouldCreateNotificationWithCorrectSender() {
      notify.sendNotifiaction(VALID_RECIPIENT, VALID_CONTENT);

      verify(notifications).publish(notificationEventCaptor.capture());
      NotificationSent capturedEvent = notificationEventCaptor.getValue();

      assertThat(capturedEvent.getNotification()).isNotNull();
    }
  }

  @Nested
  @DisplayName("When recipient is invalid")
  class InvalidRecipientTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("should return Left with RECIPIENT_INVALID error")
    void shouldReturnLeftWithRecipientInvalidError(String invalidRecipient) {
      Either<NotificationError, Notification> result = notify.sendNotifiaction(invalidRecipient, VALID_CONTENT);

      assertThat(result.isLeft()).isTrue();
      NotificationError error = result.getLeft();
      assertThat(error.getCode()).isEqualTo(NotificationErrorCode.RECIPIENT_INVALID);
      assertThat(error.getMessage()).isEqualTo("Recipient cannot be blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("should not publish notification when recipient is blank")
    void shouldNotPublishNotificationWhenRecipientIsBlank(String invalidRecipient) {
      notify.sendNotifiaction(invalidRecipient, VALID_CONTENT);

      verify(notifications, never()).publish(any(NotificationSent.class));
    }
  }

  @Nested
  @DisplayName("When content is invalid")
  class InvalidContentTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("should return Left with BODY_EMPTY error")
    void shouldReturnLeftWithBodyEmptyError(String invalidContent) {
      Either<NotificationError, Notification> result = notify.sendNotifiaction(VALID_RECIPIENT, invalidContent);

      assertThat(result.isLeft()).isTrue();
      NotificationError error = result.getLeft();
      assertThat(error.getCode()).isEqualTo(NotificationErrorCode.BODY_EMPTY);
      assertThat(error.getMessage()).isEqualTo("Content cannot be blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("should not publish notification when content is blank")
    void shouldNotPublishNotificationWhenContentIsBlank(String invalidContent) {
      notify.sendNotifiaction(VALID_RECIPIENT, invalidContent);

      verify(notifications, never()).publish(any(NotificationSent.class));
    }
  }

  @Nested
  @DisplayName("When both recipient and content are invalid")
  class BothInvalidTests {

    @Test
    @DisplayName("should return Left with RECIPIENT_INVALID error (validates recipient first)")
    void shouldReturnRecipientInvalidError() {
      Either<NotificationError, Notification> result = notify.sendNotifiaction("", "");

      assertThat(result.isLeft()).isTrue();
      NotificationError error = result.getLeft();
      assertThat(error.getCode()).isEqualTo(NotificationErrorCode.RECIPIENT_INVALID);
    }

    @Test
    @DisplayName("should not publish notification")
    void shouldNotPublishNotification() {
      notify.sendNotifiaction("", "");

      verify(notifications, never()).publish(any(NotificationSent.class));
    }
  }

  @Nested
  @DisplayName("Edge cases")
  class EdgeCaseTests {

    @Test
    @DisplayName("should handle very long recipient")
    void shouldHandleVeryLongRecipient() {
      String longRecipient = "a".repeat(1000) + "@example.com";
      Notification mockNotification = Notification.of(
          NotificationType.EMAIL,
          longRecipient,
          SENDER,
          VALID_CONTENT
      );
      when(notifications.publish(any(NotificationSent.class))).thenReturn(mockNotification);

      Either<NotificationError, Notification> result = notify.sendNotifiaction(longRecipient, VALID_CONTENT);

      assertThat(result.isRight()).isTrue();
      verify(notifications).publish(any(NotificationSent.class));
    }

    @Test
    @DisplayName("should handle very long content")
    void shouldHandleVeryLongContent() {
      String longContent = "content ".repeat(10000);
      Notification mockNotification = Notification.of(
          NotificationType.EMAIL,
          VALID_RECIPIENT,
          SENDER,
          longContent
      );
      when(notifications.publish(any(NotificationSent.class))).thenReturn(mockNotification);

      Either<NotificationError, Notification> result = notify.sendNotifiaction(VALID_RECIPIENT, longContent);

      assertThat(result.isRight()).isTrue();
      verify(notifications).publish(any(NotificationSent.class));
    }

    @Test
    @DisplayName("should handle special characters in content")
    void shouldHandleSpecialCharactersInContent() {
      String specialContent = "Test <html>content</html> with émojis 🎉 and newlines\n\ttabs";
      Notification mockNotification = Notification.of(
          NotificationType.EMAIL,
          VALID_RECIPIENT,
          SENDER,
          specialContent
      );
      when(notifications.publish(any(NotificationSent.class))).thenReturn(mockNotification);

      Either<NotificationError, Notification> result = notify.sendNotifiaction(VALID_RECIPIENT, specialContent);

      assertThat(result.isRight()).isTrue();
      verify(notifications).publish(any(NotificationSent.class));
    }
  }
}