package com.hjusic.auth.event.infrastructure;

import com.hjusic.auth.event.model.DomainEvent;
import com.hjusic.auth.event.model.DomainEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SpringDomainEventPublisher implements DomainEventPublisher {

  private final ApplicationEventPublisher applicationEventPublisher;

  @Override
  public void publish(DomainEvent event) {
    log.debug("Publishing domain event: {} with ID: {}",
        event.getClass().getSimpleName(),
        event.getEventId());
    applicationEventPublisher.publishEvent(event);
  }

  @Override
  public void publishAll(Iterable<DomainEvent> events) {
    events.forEach(this::publish);
  }
}