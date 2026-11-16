package com.hjusic.auth.domain.mfa.infrastructure.security;

import com.hjusic.auth.domain.mfa.application.VerifyTotp;
import com.hjusic.auth.domain.mfa.model.MfaErrorCode;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Verifies {@link TotpAuthenticationToken}s via the domain and grants {@code FACTOR_TOTP}.
 *
 * <p>Intentionally not a Spring bean: a second {@link AuthenticationProvider} bean would stop
 * Spring Security from wiring the global password {@code AuthenticationManager}. It is assembled
 * by {@link SecondFactorAuthenticator} instead.
 */
public class TotpAuthenticationProvider implements AuthenticationProvider {

  private final VerifyTotp verifyTotp;
  private final UserDetailsService userDetailsService;
  private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

  public TotpAuthenticationProvider(VerifyTotp verifyTotp, UserDetailsService userDetailsService) {
    this.verifyTotp = verifyTotp;
    this.userDetailsService = userDetailsService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String code = (String) authentication.getCredentials();

    var verified = verifyTotp.verify(username, code);
    if (verified.isLeft()) {
      if (verified.getLeft().getCode() == MfaErrorCode.LOCKED) {
        throw new LockedException(verified.getLeft().getMessage());
      }
      throw new BadCredentialsException("Invalid verification code");
    }

    UserDetails user = userDetailsService.loadUserByUsername(username);
    userDetailsChecker.check(user);

    List<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());
    authorities.add(SecondFactorAuthorities.grantedAuthorityOf(SecondFactorType.TOTP));
    return UsernamePasswordAuthenticationToken.authenticated(user, null, authorities);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return TotpAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
