package com.hjusic.auth.domain.user.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.user.api.dto.CreateUserRequest;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

class UserCreationIntegrationTest extends UserApiIntegrationTestBase{

  @Test
  @DisplayName("POST /api/user with admin token creates user successfully")
  void createUserAsAdmin() throws Exception {
    String adminToken = jwtService.generateToken(admin);

    CreateUserRequest request = new CreateUserRequest(
        "boba",
        "boba@fett.com",
        "SecurePass123!",
        List.of()
    );
    mockMvc.perform(post("/api/user")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(request)))
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$.username.value").value("boba"))
        .andExpect(jsonPath("$.email.value").value("boba@fett.com"));

    // Verify user was actually created in database
    var createdUser = userRepository.findByUsername("boba");
    assertTrue(createdUser.isPresent());
    assertEquals("boba@fett.com", createdUser.get().getEmail());
  }

  @Test
  @DisplayName("POST /api/user with user token failed")
  void createUserAsGuest() throws Exception {
    String adminToken = jwtService.generateToken(user);

    CreateUserRequest request = new CreateUserRequest(
        "luke",
        "luke@skywalker.com",
        "SecurePass123!",
        List.of()
    );

    mockMvc.perform(post("/api/user")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(request)))
        .andExpect(status().isForbidden());

    // Verify user was actually created in database
    var createdUser = userRepository.findByUsername("luke");
    assertTrue(createdUser.isEmpty());
  }
}
