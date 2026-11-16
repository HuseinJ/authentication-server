package com.hjusic.auth.domain.mfa.infrastructure.security;

import java.util.List;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Unauthenticated request to verify a TOTP code for a user. It is only ever created for a user who
 * already passed the password check, so it never authenticates anybody on its own. A successful
 * check yields a regular {@code UsernamePasswordAuthenticationToken} carrying
 * {@code FACTOR_TOTP}.
 */
public class TotpAuthenticationToken extends AbstractAuthenticationToken {

  private final String username;
  private @Nullable String code;

  private TotpAuthenticationToken(String username, String code) {
    super(List.of());
    this.username = username;
    this.code = code;
    setAuthenticated(false);
  }

  public static TotpAuthenticationToken unauthenticated(String username, String code) {
    return new TotpAuthenticationToken(username, code);
  }

  @Override
  public @Nullable Object getCredentials() {
    return code;
  }

  @Override
  public Object getPrincipal() {
    return username;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    code = null;
  }
}
