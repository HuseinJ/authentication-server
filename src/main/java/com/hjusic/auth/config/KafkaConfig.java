package com.hjusic.auth.config;

import com.hjusic.auth.event.model.DomainEvent;
import com.hjusic.auth.notification.model.Notification;
import com.nimbusds.jose.shaded.gson.JsonSerializer;
import java.util.HashMap;
import java.util.Map;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

@Configuration
public class KafkaConfig {

  private Map<String, Object> producerConfigs(String bootstrapServers) {
    Map<String, Object> props = new HashMap<>();
    props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
    props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
    props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
    return props;
  }

  @Bean
  public ProducerFactory<String, DomainEvent> producerFactory(
      @Value("${spring.kafka.bootstrap-servers}") String bootstrapServers) {
    return new DefaultKafkaProducerFactory<>(producerConfigs(bootstrapServers));
  }

  @Bean
  public KafkaTemplate<String, DomainEvent> kafkaTemplate(
      ProducerFactory<String, DomainEvent> producerFactory) {
    return new KafkaTemplate<>(producerFactory);
  }

  @Bean
  public ProducerFactory<String, Notification> notificationProducerFactory(
      @Value("${spring.kafka.bootstrap-servers}") String bootstrapServers) {
    return new DefaultKafkaProducerFactory<>(producerConfigs(bootstrapServers));
  }

  @Bean
  public KafkaTemplate<String, Notification> notificationKafkaTemplate(
      ProducerFactory<String, Notification> notificationProducerFactory) {
    return new KafkaTemplate<>(notificationProducerFactory);
  }
}
