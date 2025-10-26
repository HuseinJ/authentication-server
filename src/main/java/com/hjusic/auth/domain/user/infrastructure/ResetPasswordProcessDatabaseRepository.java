package com.hjusic.auth.domain.user.infrastructure;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface ResetPasswordProcessDatabaseRepository extends
    JpaRepository<ResetPasswordProcessDatabaseEntity, Long> {

  List<ResetPasswordProcessDatabaseEntity> findByUser(UserDatabaseEntity user);

  @Query("SELECT r FROM ResetPasswordProcessDatabaseEntity r JOIN FETCH r.user")
  List<ResetPasswordProcessDatabaseEntity> findAllWithUser();

  @Query("SELECT r FROM ResetPasswordProcessDatabaseEntity r JOIN FETCH r.user WHERE r.tokenHash = :tokenHash")
  Optional<ResetPasswordProcessDatabaseEntity> findByTokenHashWithUser(String tokenHash);
}
