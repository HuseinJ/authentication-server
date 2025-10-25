package com.hjusic.auth.domain.role.infrastructure;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Log4j2
public class RoleInitializer implements CommandLineRunner {

  private final RoleDatabaseRepository roleRepository;

  @Override
  public void run(String... args){
    if (roleRepository.count() == 0) {
      roleRepository.save(new RoleDatabaseEntity(RoleName.ROLE_GUEST, "Default guest role"));
      roleRepository.save(new RoleDatabaseEntity(RoleName.ROLE_ADMIN, "Default admin role"));

      log.info("Roles initialized");
    }
  }
}
