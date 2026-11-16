package com.hjusic.auth.domain.mfa;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** Test clock that MFA tests move explicitly, so TOTP time steps are deterministic. */
public class MutableClock extends Clock {

  /** Ten seconds into a 30 second TOTP step, far away from step boundaries. */
  public static final Instant DEFAULT_START = Instant.ofEpochSecond(1_800_000_010L);

  private volatile Instant instant = DEFAULT_START;

  public void set(Instant instant) {
    this.instant = instant;
  }

  public void advance(Duration duration) {
    this.instant = instant.plus(duration);
  }

  @Override
  public Instant instant() {
    return instant;
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }

  @TestConfiguration
  public static class Config {

    @Bean
    @Primary
    public MutableClock mutableClock() {
      return new MutableClock();
    }
  }
}
