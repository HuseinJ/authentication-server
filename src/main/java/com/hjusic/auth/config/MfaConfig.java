package com.hjusic.auth.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;

/**
 * Turns on Spring Security's multi-factor support.
 *
 * <p>{@code authorities} is deliberately empty: requiring factors globally would also apply to
 * the stateless bearer-token APIs. The per-user policy lives in
 * {@link com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthorizationManager} and
 * is applied to the endpoints that establish a login. What this annotation still provides is
 * authentication merging on Spring's own login filters, so e.g. a future {@code webAuthn()}
 * second step keeps the {@code FACTOR_PASSWORD} from the first step.
 */
@Configuration
@EnableMultiFactorAuthentication(authorities = {})
public class MfaConfig {

  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
