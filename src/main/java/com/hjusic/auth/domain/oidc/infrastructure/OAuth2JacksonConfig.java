package com.hjusic.auth.domain.oidc.infrastructure;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

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

  @Bean("oauth2ObjectMapper")
  public ObjectMapper oauth2ObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();

    // Whitelist your custom principal so Jackson can deserialize it
    mapper.activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder()
            .allowIfSubType(Object.class) // wide open for internal use — safe since this mapper is not exposed
            .build(),
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY
    );

    ClassLoader classLoader = OAuth2JacksonConfig.class.getClassLoader();
    mapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
    mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    mapper.registerModule(new JavaTimeModule());
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    mapper.addMixIn(UserDatabaseEntity.class, UserDatabaseEntityMixin.class);

    return mapper;
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
