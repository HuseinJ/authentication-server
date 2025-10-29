package com.hjusic.auth;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest
@Testcontainers
@ActiveProfiles({"test", "jwt", "kafka"})
@Import(TestKafkaConfig.class)
public abstract class BaseIntegrationTest {

  private static final PostgreSQLContainer<?> postgres;
  private static final KafkaContainer kafka;

  static {
    postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("testdb")
        .withUsername("testuser")
        .withPassword("testpass")
        .withReuse(true);

    kafka = new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.5.0"))
        .withReuse(true);

    postgres.start();
    kafka.start();
  }

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);

    registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
  }
}