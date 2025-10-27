package com.hjusic.auth.domain.auth.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.BaseIntegrationTest;
import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.user.infrastructure.ResetPasswordProcessDatabaseRepository;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@ActiveProfiles({"test","jwt"})
@Import(com.hjusic.auth.TestPasswordEncoderConfig.class)
class AuthControllerIntegrationTest extends BaseIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private UserDatabaseRepository userRepository;

  @Autowired
  private ResetPasswordProcessDatabaseRepository resetPasswordProcessRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @BeforeEach
  void setUp() {
    resetPasswordProcessRepository.deleteAll();
    userRepository.deleteAll();
    var user = UserDatabaseEntity.builder()
        .username("integration_user")
        .email("integration_user@example.com")
        .password(passwordEncoder.encode("password123"))
        .build();
    userRepository.save(user);
  }

  @Test
  @DisplayName("POST /api/auth/login with valid credentials returns JWT tokens")
  void loginReturnsTokens() throws Exception {
    LoginRequest req = new LoginRequest();
    req.setUsername("integration_user");
    req.setPassword("password123");

    mockMvc.perform(post("/api/auth/login")
            .contentType(APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(req)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type").value("Bearer"))
        .andExpect(jsonPath("$.token").isNotEmpty())
        .andExpect(jsonPath("$.refreshToken").isNotEmpty())
        .andExpect(jsonPath("$.expiresIn").isNumber())
        .andExpect(jsonPath("$.refreshExpiresIn").isNumber());
  }

  @Test
  @DisplayName("POST /api/auth/login with invalid credentials returns 401")
  void loginInvalidCredentials() throws Exception {
    LoginRequest req = new LoginRequest();
    req.setUsername("integration_user");
    req.setPassword("wrong");

    var result = mockMvc.perform(post("/api/auth/login")
            .contentType(APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(req)))
        .andExpect(status().is4xxClientError())
        .andReturn();

    // Optional: Ensure no token fields in error response
    String content = result.getResponse().getContentAsString();
    assertThat(content).doesNotContain("token");
  }
}
