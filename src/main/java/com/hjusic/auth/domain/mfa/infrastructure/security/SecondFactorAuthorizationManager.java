package com.hjusic.auth.domain.mfa.infrastructure.security;

import com.hjusic.auth.domain.mfa.application.SecondFactorRegistry;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import java.util.Set;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Per-user MFA policy on top of Spring Security's factor authorization: the password factor is
 * always required, and users who enrolled second factors must additionally present any one of
 * them. Denials are {@code FactorAuthorizationDecision}s naming the missing {@code FACTOR_*}
 * authorities, which is what {@code DelegatingMissingAuthorityAccessDeniedHandler} routes on.
 */
@Component
@RequiredArgsConstructor
public class SecondFactorAuthorizationManager implements AuthorizationManager<Object> {

  private static final RequiredFactor PASSWORD =
      RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).build();

  private final SecondFactorRegistry secondFactorRegistry;
  private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

  @Override
  public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
      Object object) {
    Authentication current = authentication.get();
    Set<SecondFactorType> enrolled = trustResolver.isAuthenticated(current)
        ? secondFactorRegistry.enrolledFactors(current.getName())
        : Set.of();

    if (enrolled.isEmpty()) {
      return AllRequiredFactorsAuthorizationManager.builder()
          .requireFactor(PASSWORD)
          .build()
          .authorize(authentication, object);
    }

    @SuppressWarnings("unchecked")
    AllRequiredFactorsAuthorizationManager<Object>[] anyOf = enrolled.stream()
        .map(type -> AllRequiredFactorsAuthorizationManager.builder()
            .requireFactor(PASSWORD)
            .requireFactor(f -> f.authority(SecondFactorAuthorities.authorityOf(type)))
            .build())
        .toArray(AllRequiredFactorsAuthorizationManager[]::new);
    return AllRequiredFactorsAuthorizationManager.anyOf(anyOf).authorize(authentication, object);
  }
}
