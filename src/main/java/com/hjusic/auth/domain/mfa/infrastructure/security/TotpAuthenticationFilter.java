package com.hjusic.auth.domain.mfa.infrastructure.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Second step of the session (OIDC) login: reads {@code code} from the POSTed form and verifies it
 * for the user who already signed in with their password in this session.
 *
 * <p>Runs with Spring Security's MFA merging enabled, so the resulting authentication keeps the
 * existing {@code FACTOR_PASSWORD} and adds {@code FACTOR_TOTP}, which is exactly what
 * {@link SecondFactorAuthorizationManager} asks for on {@code /oauth2/authorize}.
 */
public class TotpAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  public static final String CODE_PARAMETER = "code";

  private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

  public TotpAuthenticationFilter(String processingUrl, AuthenticationManager authenticationManager) {
    super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, processingUrl),
        authenticationManager);
    setMfaEnabled(true);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    Authentication current = SecurityContextHolder.getContextHolderStrategy().getContext()
        .getAuthentication();
    if (!trustResolver.isAuthenticated(current) || !hasPasswordFactor(current)) {
      throw new InsufficientAuthenticationException(
          "Sign in with your password before entering a verification code");
    }

    String code = request.getParameter(CODE_PARAMETER);
    return getAuthenticationManager().authenticate(
        TotpAuthenticationToken.unauthenticated(current.getName(), code == null ? "" : code));
  }

  private static boolean hasPasswordFactor(Authentication authentication) {
    return authentication.getAuthorities().stream()
        .anyMatch(a -> FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(a.getAuthority()));
  }
}
