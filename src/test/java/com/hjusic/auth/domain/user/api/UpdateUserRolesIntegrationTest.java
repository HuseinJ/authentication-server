package com.hjusic.auth.domain.user.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseRepository;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.api.dto.UpdateRoleRequest;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("Update User Roles Integration Tests")
class UpdateUserRolesIntegrationTest extends UserApiIntegrationTestBase {

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private RoleDatabaseRepository roleRepository;

  @Test
  @DisplayName("Should allow admin to update user roles successfully")
  void shouldAllowAdminToUpdateUserRoles() throws Exception {
    // Given
    var adminToken = jwtService.generateToken(admin);

    UpdateRoleRequest updateRequest = new UpdateRoleRequest();
    updateRequest.setRoles(Set.of(RoleName.ROLE_ADMIN, RoleName.ROLE_GUEST));

    // When
    mockMvc.perform(post("/api/user/roles/{username}", user.getUsername())
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(updateRequest)))
        .andExpect(status().isOk());

    // Then
    UserDatabaseEntity updatedUser = userRepository.findByUsername(user.getUsername()).orElseThrow();
    assertThat(updatedUser.getRoles())
        .extracting(r -> r.getName())
        .contains(RoleName.ROLE_ADMIN)
        .contains(RoleName.ROLE_GUEST);
  }

  @Test
  @DisplayName("Should reject role update if not admin")
  void shouldRejectRoleUpdateIfNotAdmin() throws Exception {
    // Given - a normal user (ROLE_GUEST)
    var userToken = jwtService.generateToken(user);

    UpdateRoleRequest updateRequest = new UpdateRoleRequest();
    updateRequest.setRoles(Set.of(RoleName.ROLE_ADMIN));

    // When / Then
    mockMvc.perform(post("/api/user/roles/{username}", user.getUsername())
            .header("Authorization", "Bearer " + userToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(updateRequest)))
        .andExpect(status().isForbidden());
  }

  @Test
  @DisplayName("Should return 400 when updating non-existent user")
  void shouldReturnBadRequestWhenUserNotFound() throws Exception {
    // Given
    var adminToken = jwtService.generateToken(admin);

    UpdateRoleRequest updateRequest = new UpdateRoleRequest();
    updateRequest.setRoles(Set.of(RoleName.ROLE_GUEST));

    // When / Then
    mockMvc.perform(post("/api/user/roles/{username}", "unknownUser")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(updateRequest)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("User does not exist"));
  }

  @Test
  @DisplayName("Should reject unauthenticated request")
  void shouldRejectUnauthenticatedRequest() throws Exception {
    // Given
    UpdateRoleRequest updateRequest = new UpdateRoleRequest();
    updateRequest.setRoles(Set.of(RoleName.ROLE_ADMIN));

    // When / Then
    mockMvc.perform(post("/api/user/roles/{username}", user.getUsername())
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(updateRequest)))
        .andExpect(status().isForbidden());
  }
}