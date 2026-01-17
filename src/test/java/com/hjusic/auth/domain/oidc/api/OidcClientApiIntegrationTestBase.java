package com.hjusic.auth.domain.oidc.api;

import com.hjusic.auth.BaseIntegrationTest;
import com.hjusic.auth.domain.oidc.infrastructure.OidcClientDatabaseEntity;
import com.hjusic.auth.domain.oidc.infrastructure.OidcClientDatabaseRepository;
import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseRepository;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.infrastructure.ResetPasswordProcessDatabaseRepository;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@AutoConfigureMockMvc
@ActiveProfiles({"test", "jwt"})
@Import(com.hjusic.auth.TestPasswordEncoderConfig.class)
public abstract class OidcClientApiIntegrationTestBase extends BaseIntegrationTest {

  @Autowired
  protected MockMvc mockMvc;

  @Autowired
  protected OidcClientDatabaseRepository oidcClientRepository;

  @Autowired
  protected UserDatabaseRepository userRepository;

  @Autowired
  protected RoleDatabaseRepository roleDatabaseRepository;

  @Autowired
  protected ResetPasswordProcessDatabaseRepository resetPasswordProcessRepository;

  @Autowired
  protected PasswordEncoder passwordEncoder;

  @Autowired
  protected com.hjusic.auth.service.JwtService jwtService;

  protected UserDatabaseEntity admin;
  protected UserDatabaseEntity user;
  protected OidcClientDatabaseEntity existingClient;

  @BeforeEach
  void commonSetUp() {
    // Delete in correct order to respect foreign key constraints
    oidcClientRepository.deleteAll();
    resetPasswordProcessRepository.deleteAll();
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

    existingClient = OidcClientDatabaseEntity.builder()
        .id(UUID.randomUUID().toString())
        .clientId("test-client")
        .clientSecret("hashed-secret")
        .clientName("Test Client")
        .grantTypes(Set.of("authorization_code", "refresh_token"))
        .authenticationMethods(Set.of("client_secret_basic"))
        .redirectUris(Set.of("https://example.com/callback"))
        .postLogoutRedirectUris(Set.of("https://example.com/logout"))
        .scopes(Set.of("openid", "profile"))
        .accessTokenTimeToLiveSeconds(3600L)
        .refreshTokenTimeToLiveSeconds(86400L)
        .authorizationCodeTimeToLiveSeconds(300L)
        .reuseRefreshTokens(false)
        .requireProofKey(false)
        .requireAuthorizationConsent(true)
        .clientIdIssuedAt(Instant.now())
        .build();

    oidcClientRepository.save(existingClient);
  }
}