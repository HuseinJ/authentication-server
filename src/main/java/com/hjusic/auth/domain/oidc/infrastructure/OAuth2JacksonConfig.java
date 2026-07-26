package com.hjusic.auth.domain.oidc.infrastructure;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson.SecurityJacksonModules;
import tools.jackson.databind.DefaultTyping;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

@Configuration
public class OAuth2JacksonConfig {

  @Bean
  @Primary
  public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule());
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    return mapper;
  }

  // Jackson 3 mapper: the Spring Security modules ship as Jackson 3 (tools.jackson)
  // modules, so this mapper is configured immutably via the JsonMapper builder.
  // JSR-310 support is built into Jackson 3 databind, so no JavaTimeModule is registered.
  //
  // The return type is deliberately the parent ObjectMapper, not JsonMapper: exposing a
  // JsonMapper bean would satisfy Spring Boot's @ConditionalOnMissingBean(JsonMapper) and
  // make this default-typing mapper the primary one used for HTTP message conversion.
  @Bean("oauth2ObjectMapper")
  public tools.jackson.databind.ObjectMapper oauth2ObjectMapper() {
    ClassLoader classLoader = OAuth2JacksonConfig.class.getClassLoader();

    // Let the Spring Security modules register the subtypes they need on the
    // polymorphic type validator, and additionally trust this application's own
    // principal/entity classes (e.g. UserDatabaseEntity stored as the principal).
    // getModules(..) also bundles the OAuth2 authorization-server module when present.
    BasicPolymorphicTypeValidator.Builder ptvBuilder = BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.hjusic.auth.");
    var securityModules = SecurityJacksonModules.getModules(classLoader, ptvBuilder);

    return JsonMapper.builder()
        .activateDefaultTyping(
            ptvBuilder.build(),
            DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY
        )
        .addModules(securityModules)
        .addMixIn(UserDatabaseEntity.class, UserDatabaseEntityMixin.class)
        .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
        .build();
  }

  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  @JsonAutoDetect(
      fieldVisibility    = JsonAutoDetect.Visibility.ANY,
      getterVisibility   = JsonAutoDetect.Visibility.NONE,
      isGetterVisibility = JsonAutoDetect.Visibility.NONE
  )
  @JsonIgnoreProperties(ignoreUnknown = true)
  abstract static class UserDatabaseEntityMixin {
    @JsonIgnore
    abstract java.util.Set<?> getRoles();
  }
}
