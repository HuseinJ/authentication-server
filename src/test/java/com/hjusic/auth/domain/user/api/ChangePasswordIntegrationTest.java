package com.hjusic.auth.domain.user.api;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.user.api.dto.ChangePasswordRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("Change Password Integration Tests")
class ChangePasswordIntegrationTest extends UserApiIntegrationTestBase {

  @Autowired
  private ObjectMapper objectMapper;

  @Test
  @DisplayName("PUT /api/user/password with valid old password changes password successfully")
  void changePasswordSuccessfully() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Password successfully changed"));

    // Verify the new password works by checking the hash
    var updatedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("NewSecurePass456!", updatedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with incorrect old password fails")
  void changePasswordWithWrongOldPassword() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "wrongOldPassword",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists())
        .andExpect(jsonPath("$.error").value("Old password does not match"));

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password without authentication fails")
  void changePasswordWithoutAuth() throws Exception {
    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isForbidden());

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with invalid token fails")
  void changePasswordWithInvalidToken() throws Exception {
    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer invalid.token.here")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isUnauthorized());

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with empty old password fails")
  void changePasswordWithEmptyOldPassword() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists())
        .andExpect(jsonPath("$.error").value("Old password cannot be empty"));

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with null old password fails")
  void changePasswordWithNullOldPassword() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        null,
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with weak new password fails")
  void changePasswordWithWeakNewPassword() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "weak"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with blank old password fails")
  void changePasswordWithBlankOldPassword() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "   ",
        "NewSecurePass456!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists())
        .andExpect(jsonPath("$.error").value("Old password cannot be empty"));

    // Verify password was NOT changed
    var unchangedUser = userRepository.findByUsername("user").get();
    assertTrue(passwordEncoder.matches("password123", unchangedUser.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password admin can change their own password")
  void adminCanChangeTheirPassword() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "NewAdminPass789!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Password successfully changed"));

    // Verify the new password works
    var updatedAdmin = userRepository.findByUsername("admin").get();
    assertTrue(passwordEncoder.matches("NewAdminPass789!", updatedAdmin.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password changes only the authenticated user's password")
  void changePasswordOnlyAffectsAuthenticatedUser() throws Exception {
    String userToken = jwtService.generateToken(user);

    ChangePasswordRequest request = new ChangePasswordRequest(
        "password123",
        "NewUserPass999!"
    );

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isOk());

    // Verify only user's password changed, not admin's
    var updatedUser = userRepository.findByUsername("user").get();
    var unchangedAdmin = userRepository.findByUsername("admin").get();

    assertTrue(passwordEncoder.matches("NewUserPass999!", updatedUser.getPassword()));
    assertTrue(passwordEncoder.matches("password123", unchangedAdmin.getPassword()));
  }

  @Test
  @DisplayName("PUT /api/user/password with missing request body fails")
  void changePasswordWithMissingBody() throws Exception {
    String userToken = jwtService.generateToken(user);

    mockMvc.perform(put("/api/user/password")
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isBadRequest());
  }
}