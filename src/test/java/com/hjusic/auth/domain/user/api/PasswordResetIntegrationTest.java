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

  @Test
  @DisplayName("Should reject token when used multiple times")
  void shouldRejectTokenWhenUsedMultipleTimes() throws Exception {
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

    // Step 2: Create reset process with known token
    var createdUser = userRepository.findByUsername("testuser").get();
    String knownToken = "test-token-12345678";
    String tokenHash = hashToken(knownToken);

    ResetPasswordProcessDatabaseEntity resetProcess = ResetPasswordProcessDatabaseEntity.builder()
        .user(createdUser)
        .tokenHash(tokenHash)
        .createdAt(java.time.LocalDateTime.now())
        .expiresAt(java.time.LocalDateTime.now().plusHours(1))
        .build();

    resetPasswordProcessRepository.save(resetProcess);

    // Step 3: Complete password reset FIRST TIME - should succeed
    CompleteResetPasswordRequest firstRequest = new CompleteResetPasswordRequest();
    firstRequest.setUsername("testuser");
    firstRequest.setToken(knownToken);
    firstRequest.setNewPassword("NewPassword123!");

    mockMvc.perform(post("/api/user/password-reset/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(firstRequest)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Password successfully reset"));

    // Step 4: Try to use same token SECOND TIME - should fail
    CompleteResetPasswordRequest secondRequest = new CompleteResetPasswordRequest();
    secondRequest.setUsername("testuser");
    secondRequest.setToken(knownToken);
    secondRequest.setNewPassword("AnotherPassword456!");

    mockMvc.perform(post("/api/user/password-reset/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(secondRequest)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("Invalid or expired reset token"));

    // Step 5: Verify password is still the first new password (not the second attempt)
    var updatedUser = userRepository.findByUsername("testuser").get();
    assertThat(passwordEncoder.matches("NewPassword123!", updatedUser.getPassword()))
        .describedAs("Password should be the first reset, not the second")
        .isTrue();
    assertThat(passwordEncoder.matches("AnotherPassword456!", updatedUser.getPassword()))
        .describedAs("Second password change should have been rejected")
        .isFalse();

    // Step 6: Verify reset process is marked as used
    var usedResetProcess = resetPasswordProcessRepository.findAllWithUser().get(0);
    assertThat(usedResetProcess.isUsed()).isTrue();
    assertThat(usedResetProcess.getUsedAt()).isNotNull();
  }

  @Test
  @DisplayName("Should reject expired token")
  void shouldRejectExpiredToken() throws Exception {
    // Setup user
    var createdUser = userRepository.findByUsername("user").get();
    String knownToken = "expired-token-123";
    String tokenHash = hashToken(knownToken);

    // Create EXPIRED reset process
    ResetPasswordProcessDatabaseEntity expiredProcess = ResetPasswordProcessDatabaseEntity.builder()
        .user(createdUser)
        .tokenHash(tokenHash)
        .createdAt(java.time.LocalDateTime.now().minusHours(2))
        .expiresAt(java.time.LocalDateTime.now().minusHours(1)) // Expired 1 hour ago
        .build();

    resetPasswordProcessRepository.save(expiredProcess);

    // Try to use expired token
    CompleteResetPasswordRequest request = new CompleteResetPasswordRequest();
    request.setUsername("user");
    request.setToken(knownToken);
    request.setNewPassword("NewPassword123!");

    mockMvc.perform(post("/api/user/password-reset/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("Invalid or expired reset token"));

    // Verify password wasn't changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertThat(passwordEncoder.matches("password123", unchangedUser.getPassword()))
        .describedAs("Password should remain unchanged when using expired token")
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