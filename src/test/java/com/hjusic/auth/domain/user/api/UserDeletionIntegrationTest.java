package com.hjusic.auth.domain.user.api;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class UserDeletionIntegrationTest extends UserApiIntegrationTestBase {

  @Test
  @DisplayName("DELETE /api/user/{username} with admin token deletes user successfully")
  void deleteUserAsAdmin() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(delete("/api/user/{username}", "user")
            .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.username.value").value("user"))
        .andExpect(jsonPath("$.email.value").value("user@example.com"));

    // Verify user was actually deleted from database
    var deletedUser = userRepository.findByUsername("user");
    assertTrue(deletedUser.isEmpty());
  }

  @Test
  @DisplayName("DELETE /api/user/{username} with guest token fails")
  void deleteUserAsGuest() throws Exception {
    String userToken = jwtService.generateToken(user);

    mockMvc.perform(delete("/api/user/{username}", "admin")
            .header("Authorization", "Bearer " + userToken))
        .andExpect(status().isForbidden());

    // Verify user was NOT deleted from database
    var existingUser = userRepository.findByUsername("admin");
    assertTrue(existingUser.isPresent());
  }

  @Test
  @DisplayName("DELETE /api/user/{username} without authentication fails")
  void deleteUserWithoutAuth() throws Exception {
    mockMvc.perform(delete("/api/user/{username}", "user"))
        .andExpect(status().isForbidden());

    // Verify user was NOT deleted from database
    var existingUser = userRepository.findByUsername("user");
    assertTrue(existingUser.isPresent());
  }

  @Test
  @DisplayName("DELETE /api/user/{username} with invalid token fails")
  void deleteUserWithInvalidToken() throws Exception {
    mockMvc.perform(delete("/api/user/{username}", "user")
            .header("Authorization", "Bearer invalid.token.here"))
        .andExpect(status().isUnauthorized());

    // Verify user was NOT deleted from database
    var existingUser = userRepository.findByUsername("user");
    assertTrue(existingUser.isPresent());
  }

  @Test
  @DisplayName("DELETE /api/user/{username} with non-existent username returns error")
  void deleteNonExistentUser() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(delete("/api/user/{username}", "nonexistent")
            .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());

    // Verify no user was deleted
    var allUsers = userRepository.findAll();
    assertTrue(allUsers.size() >= 2); // admin and user still exist
  }

  @Test
  @DisplayName("DELETE /api/user/{username} with empty username returns error")
  void deleteUserWithEmptyUsername() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(delete("/api/user/{username}", "   ")
            .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());
  }

  @Test
  @DisplayName("DELETE /api/user/{username} admin cannot delete themselves")
  void adminCannotDeleteThemselves() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(delete("/api/user/{username}", "admin")
            .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").exists());

    // Verify admin still exists
    var adminUser = userRepository.findByUsername("admin");
    assertTrue(adminUser.isPresent());
  }
}