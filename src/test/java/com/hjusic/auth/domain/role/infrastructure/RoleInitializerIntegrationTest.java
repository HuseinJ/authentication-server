package com.hjusic.auth.domain.role.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.BaseIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class RoleInitializerIntegrationTest extends BaseIntegrationTest {

  @Autowired
  private RoleDatabaseRepository roleRepository;

  @Test
  void shouldInitializeBaseRoles() {
    assertThat(roleRepository.count()).isEqualTo(RoleName.values().length);
  }

}