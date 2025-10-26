package com.hjusic.auth.domain.user.infrastructure;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ResetPasswordProcessDatabaseRepository extends
    JpaRepository<ResetPasswordProcessDatabaseEntity, Long> {

  List<ResetPasswordProcessDatabaseEntity> findByUser(UserDatabaseEntity user);
}
