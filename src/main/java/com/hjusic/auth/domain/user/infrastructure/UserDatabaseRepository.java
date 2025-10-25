package com.hjusic.auth.domain.user.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserDatabaseRepository extends JpaRepository<UserDatabaseEntity, Long> {

  Optional<UserDatabaseEntity> findByUsername(String username);

  Optional<UserDatabaseEntity> findByEmail(String email);

  boolean existsByUsername(String username);

  boolean existsByEmail(String email);
}
