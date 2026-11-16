package com.hjusic.auth.domain.mfa.infrastructure.security;

import com.hjusic.auth.domain.mfa.application.VerifyTotp;
import java.util.List;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

/**
 * The {@link AuthenticationManager} for second-factor steps, kept separate from the password
 * manager. Code-based factors (TOTP, later e.g. recovery codes) register their provider here;
 * WebAuthn would use Spring Security's own {@code webAuthn()} filter instead.
 *
 * <p>Exposed as a plain component rather than an {@code AuthenticationManager} bean so it cannot
 * be picked up as the application's global authentication manager.
 */
@Component
public class SecondFactorAuthenticator {

  private final ProviderManager providerManager;

  public SecondFactorAuthenticator(VerifyTotp verifyTotp, UserDetailsService userDetailsService) {
    this.providerManager = new ProviderManager(List.of(
        new TotpAuthenticationProvider(verifyTotp, userDetailsService)));
  }

  public Authentication authenticate(Authentication authentication)
      throws AuthenticationException {
    return providerManager.authenticate(authentication);
  }

  public AuthenticationManager asAuthenticationManager() {
    return this::authenticate;
  }
}
