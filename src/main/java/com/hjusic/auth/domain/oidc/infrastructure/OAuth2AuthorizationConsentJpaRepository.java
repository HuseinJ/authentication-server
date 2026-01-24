package com.hjusic.auth.domain.oidc.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationConsentJpaRepository
    extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntity.AuthorizationConsentId> {

  Optional<OAuth2AuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(
      String registeredClientId, String principalName);

  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}