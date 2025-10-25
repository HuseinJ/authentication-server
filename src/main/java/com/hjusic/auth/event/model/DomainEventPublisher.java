package com.hjusic.auth.event.model;

public interface DomainEventPublisher {
  void publish(DomainEvent event);

  void publishAll(Iterable<DomainEvent> events);
}
