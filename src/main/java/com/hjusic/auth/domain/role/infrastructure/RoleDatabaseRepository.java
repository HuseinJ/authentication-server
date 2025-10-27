package com.hjusic.auth.domain.role.infrastructure;

import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleDatabaseRepository extends JpaRepository<RoleDatabaseEntity, Long> {
  Optional<RoleDatabaseEntity> findByName(RoleName name);
  Set<RoleDatabaseEntity> findAllByNameIn(Collection<RoleName> names);
  List<RoleDatabaseEntity> findAllByUsersContains(UserDatabaseEntity user);
  boolean existsByName(RoleName name);
}