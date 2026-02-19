package com.hjusic.auth.domain.oidc.infrastructure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
    ClassLoader classLoader = OAuth2JacksonConfig.class.getClassLoader();
    mapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
    mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    return mapper;
  }

}
