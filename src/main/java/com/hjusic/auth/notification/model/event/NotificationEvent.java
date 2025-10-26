package com.hjusic.auth.notification.model.event;

import com.hjusic.auth.event.model.DomainEvent;
import com.hjusic.auth.notification.model.Notification;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class NotificationEvent extends DomainEvent {

  private Notification notification;
}
