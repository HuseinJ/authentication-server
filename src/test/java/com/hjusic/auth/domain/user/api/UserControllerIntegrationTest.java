package com.hjusic.auth.domain.user.api;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class UserControllerIntegrationTest extends UserApiIntegrationTestBase {

  @Test
  @DisplayName("GET /api/user with admin token returns user list")
  void getUsersAsAdmin() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    mockMvc.perform(get("/api/user")
            .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$").isArray())
        .andExpect(jsonPath("$.length()").value(2))
        .andExpect(jsonPath("$[?(@.username.value == 'admin')]").exists())
        .andExpect(jsonPath("$[?(@.username.value == 'user')]").exists())
        .andExpect(jsonPath("$[?(@.email.value == 'admin@example.com')]").exists())
        .andExpect(jsonPath("$[?(@.email.value == 'user@example.com')]").exists());
  }

  @Test
  @DisplayName("GET /api/user without authentication returns 403")
  void getUsersWithoutAuthReturns403() throws Exception {
    mockMvc.perform(get("/api/user"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.length()").doesNotExist());
  }

  @Test
  @DisplayName("GET /api/user with non-admin token returns 403")
  void getUsersAsNonAdminReturns403() throws Exception {
    String userToken = jwtService.generateToken(user);

    mockMvc.perform(get("/api/user")
            .header("Authorization", "Bearer " + userToken))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.length()").doesNotExist());
  }

  @Test
  @DisplayName("GET /api/user with invalid token returns 401")
  void getUsersWithInvalidTokenReturns401() throws Exception {
    mockMvc.perform(get("/api/user")
            .header("Authorization", "Bearer invalid.token.here"))
        .andExpect(status().isUnauthorized());
  }

}
