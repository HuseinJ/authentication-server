package com.hjusic.auth.domain.role.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleDatabaseRepository extends JpaRepository<RoleDatabaseEntity, Long> {
  Optional<RoleDatabaseEntity> findByName(RoleName name);
  boolean existsByName(RoleName name);
}