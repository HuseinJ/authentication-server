package com.hjusic.auth.domain.user.api;

import com.hjusic.auth.BaseIntegrationTest;
import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseRepository;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseRepository;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
@ActiveProfiles({"test", "jwt"})
@Import(com.hjusic.auth.TestPasswordEncoderConfig.class)
public abstract class UserApiIntegrationTestBase extends BaseIntegrationTest {

  @Autowired
  protected MockMvc mockMvc;

  @Autowired
  protected UserDatabaseRepository userRepository;

  @Autowired
  protected RoleDatabaseRepository roleDatabaseRepository;

  @Autowired
  protected PasswordEncoder passwordEncoder;

  @Autowired
  protected com.hjusic.auth.service.JwtService jwtService;

  protected UserDatabaseEntity admin;
  protected UserDatabaseEntity user;

  @BeforeEach
  void commonSetUp() {
    userRepository.deleteAll();
    var adminRole = roleDatabaseRepository.findByName(RoleName.ROLE_ADMIN).get();
    var guestRole = roleDatabaseRepository.findByName(RoleName.ROLE_GUEST).get();

    admin = UserDatabaseEntity.builder()
        .username("admin")
        .email("admin@example.com")
        .roles(Set.of(adminRole))
        .password(passwordEncoder.encode("password123"))
        .build();

    user = UserDatabaseEntity.builder()
        .username("user")
        .email("user@example.com")
        .roles(Set.of(guestRole))
        .password(passwordEncoder.encode("password123"))
        .build();

    userRepository.save(user);
    userRepository.save(admin);
  }
}
