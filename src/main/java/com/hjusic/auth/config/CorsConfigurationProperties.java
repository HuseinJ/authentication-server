package com.hjusic.auth.config;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.cors")
public class CorsConfigurationProperties {
  private List<String> allowedOrigins;
}
