package com.hjusic.auth.domain.user.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.user.api.dto.CompleteResetPasswordRequest;
import com.hjusic.auth.domain.user.api.dto.CreateUserRequest;
import com.hjusic.auth.domain.user.api.dto.InitiateResetPasswordRequest;
import com.hjusic.auth.domain.user.infrastructure.ResetPasswordProcessDatabaseEntity;
import com.hjusic.auth.domain.user.infrastructure.ResetPasswordProcessDatabaseRepository;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("Password Reset Integration Tests")
class PasswordResetIntegrationTest extends UserApiIntegrationTestBase {

  @Autowired
  private ResetPasswordProcessDatabaseRepository resetProcessRepository;

  @Autowired
  private ObjectMapper objectMapper;

  @Test
  @DisplayName("Should initiate reset and create database entry")
  void shouldInitiatePasswordReset() throws Exception {
    // Given
    InitiateResetPasswordRequest request = new InitiateResetPasswordRequest();
    request.setUsername("user");

    // When
    mockMvc.perform(post("/api/user/password-reset/initiate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk());

    // Then
    var resetProcesses = resetProcessRepository.findAllWithUser();
    assertThat(resetProcesses).hasSize(1);
    assertThat(resetProcesses.get(0).getUser().getUsername()).isEqualTo("user");
    assertThat(resetProcesses.get(0).getTokenHash()).isNotNull();
  }

  @Test
  @DisplayName("Should not leak user existence (security)")
  void shouldNotLeakUserExistence() throws Exception {
    // Given - non-existent user
    InitiateResetPasswordRequest request = new InitiateResetPasswordRequest();
    request.setUsername("nonexistent");

    // When
    mockMvc.perform(post("/api/user/password-reset/initiate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").exists());

    // Then - no reset process created
    assertThat(resetProcessRepository.findAll()).isEmpty();
  }

  @Test
  @DisplayName("Should reject invalid token")
  void shouldRejectInvalidToken() throws Exception {
    // Given
    CompleteResetPasswordRequest request = new CompleteResetPasswordRequest();
    request.setUsername("user");
    request.setToken("invalid-token");
    request.setNewPassword("NewSecure123!");

    // When
    mockMvc.perform(post("/api/user/password-reset/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());
  }

  @Test
  @DisplayName("Should work without authentication")
  void shouldWorkWithoutAuth() throws Exception {
    // Given
    InitiateResetPasswordRequest request = new InitiateResetPasswordRequest();
    request.setUsername("user");

    // When - no auth header
    mockMvc.perform(post("/api/user/password-reset/initiate")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("Complete flow: Create user → Reset password → Login with new password")
  void completePasswordResetFlow() throws Exception {
    // Step 1: Create user
    CreateUserRequest createRequest = new CreateUserRequest(
        "testuser",
        "testuser@example.com",
        "OldPassword123!",
        List.of()
    );

    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(post("/api/user")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(createRequest)))
        .andExpect(status().is2xxSuccessful());

    // Step 2: Manually create reset process with known token (for testing)
    var createdUser = userRepository.findByUsername("testuser").get();
    String knownToken = "test-token-12345678";
    String tokenHash = hashToken(knownToken); // Use your TokenHashingUtil

    ResetPasswordProcessDatabaseEntity resetProcess = ResetPasswordProcessDatabaseEntity.builder()
        .user(createdUser)
        .tokenHash(tokenHash)
        .createdAt(java.time.LocalDateTime.now())
        .expiresAt(java.time.LocalDateTime.now().plusHours(1))
        .build();

    resetPasswordProcessRepository.save(resetProcess);

    // Step 3: Complete password reset
    CompleteResetPasswordRequest completeRequest = new CompleteResetPasswordRequest();
    completeRequest.setUsername("testuser");
    completeRequest.setToken(knownToken);
    completeRequest.setNewPassword("NewSecurePassword456!");

    mockMvc.perform(post("/api/user/password-reset/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(completeRequest)))
        .andExpect(status().isOk());

    // Step 4: Login with new password
    String loginRequest = """
      {
        "username": "testuser",
        "password": "NewSecurePassword456!"
      }
      """;

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(loginRequest))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.token").exists());

    // Verify password was actually changed
    var updatedUser = userRepository.findByUsername("testuser").get();
    assertThat(passwordEncoder.matches("NewSecurePassword456!", updatedUser.getPassword()))
        .isTrue();
  }

  private String hashToken(String rawToken) {
    try {
      java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(rawToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      StringBuilder hexString = new StringBuilder(2 * hash.length);
      for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}