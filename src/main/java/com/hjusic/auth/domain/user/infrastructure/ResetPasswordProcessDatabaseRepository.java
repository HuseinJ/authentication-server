package com.hjusic.auth.domain.user.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ResetPasswordProcessDatabaseRepository extends
    JpaRepository<ResetPasswordProcessDatabaseEntity, Long> {

}
