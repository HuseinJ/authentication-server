package com.hjusic.auth.domain.oidc.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OidcClientDatabaseRepository extends JpaRepository<OidcClientDatabaseEntity, String> {

  Optional<OidcClientDatabaseEntity> findByClientId(String clientId);

  boolean existsByClientId(String clientId);
}