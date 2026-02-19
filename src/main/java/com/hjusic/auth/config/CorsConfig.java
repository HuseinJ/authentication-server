package com.hjusic.auth.config;

import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
@Log4j2
public class CorsConfig {

  private final CorsConfigurationProperties corsProperties;

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    log.warn("Initializing CORS Configuration");

    List<String> allowedOrigins = corsProperties.getAllowedOrigins();

    if (allowedOrigins == null || allowedOrigins.isEmpty()) {
      log.error("No allowed origins configured! Set 'auth.cors.allowed-origins' in application.yml");
      return null;
    }

    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(allowedOrigins);
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);
    configuration.setExposedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    log.info("CORS allowed origins: {}", allowedOrigins);
    return source;
  }
}