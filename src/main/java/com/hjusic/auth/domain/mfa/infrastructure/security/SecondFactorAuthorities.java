package com.hjusic.auth.domain.mfa.infrastructure.security;

import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import java.util.Optional;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/** Maps domain factors onto Spring Security's {@code FACTOR_*} authorities. */
public final class SecondFactorAuthorities {

  private static final String PREFIX = "FACTOR_";

  private SecondFactorAuthorities() {
  }

  public static String authorityOf(SecondFactorType type) {
    return PREFIX + type.getFactor();
  }

  public static FactorGrantedAuthority grantedAuthorityOf(SecondFactorType type) {
    return FactorGrantedAuthority.fromFactor(type.getFactor());
  }

  public static Optional<SecondFactorType> typeOf(String authority) {
    if (authority == null || !authority.startsWith(PREFIX)) {
      return Optional.empty();
    }
    return SecondFactorType.fromFactor(authority.substring(PREFIX.length()));
  }
}
