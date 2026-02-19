package com.hjusic.auth.domain.oidc.infrastructure;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

  private final OAuth2AuthorizationConsentJpaRepository consentRepository;
  private final RegisteredClientRepository registeredClientRepository;

  @Override
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    var entity = toEntity(authorizationConsent);
    consentRepository.save(entity);
  }

  @Override
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    consentRepository.deleteByRegisteredClientIdAndPrincipalName(
        authorizationConsent.getRegisteredClientId(),
        authorizationConsent.getPrincipalName()
    );
  }

  @Override
  public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
    return consentRepository.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
        .map(this::toAuthorizationConsent)
        .orElse(null);
  }

  private OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent consent) {
    Set<String> authorities = new HashSet<>();
    consent.getAuthorities().forEach(authority -> authorities.add(authority.getAuthority()));

    return OAuth2AuthorizationConsentEntity.builder()
        .registeredClientId(consent.getRegisteredClientId())
        .principalName(consent.getPrincipalName())
        .authorities(StringUtils.collectionToDelimitedString(authorities, ","))
        .build();
  }

  private OAuth2AuthorizationConsent toAuthorizationConsent(OAuth2AuthorizationConsentEntity entity) {
    var registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
    if (registeredClient == null) {
      throw new IllegalStateException("Registered client not found: " + entity.getRegisteredClientId());
    }

    var builder = OAuth2AuthorizationConsent.withId(
        entity.getRegisteredClientId(),
        entity.getPrincipalName()
    );

    Set<String> authorities = StringUtils.commaDelimitedListToSet(entity.getAuthorities());
    authorities.forEach(authority -> {
      if (authority.startsWith("SCOPE_")) {
        builder.scope(authority.substring(6));
      } else {
        builder.authority(new SimpleGrantedAuthority(authority));
      }
    });

    return builder.build();
  }
}