package com.hjusic.auth.domain.oidc.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class OidcClientControllerIntegrationTest extends OidcClientApiIntegrationTestBase {

  @Autowired
  private ObjectMapper objectMapper;

  @Nested
  @DisplayName("GET /api/oidc/clients")
  class GetAllClients {

    @Test
    @DisplayName("with admin token returns client list")
    void getAllClientsAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(get("/api/oidc/clients")
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$").isArray())
          .andExpect(jsonPath("$", hasSize(1)))
          .andExpect(jsonPath("$[0].clientId.value").value("test-client"))
          .andExpect(jsonPath("$[0].clientName.value").value("Test Client"));
    }

    @Test
    @DisplayName("without authentication returns 403")
    void getAllClientsWithoutAuthReturns403() throws Exception {
      mockMvc.perform(get("/api/oidc/clients"))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void getAllClientsAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      mockMvc.perform(get("/api/oidc/clients")
              .header("Authorization", "Bearer " + userToken))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with invalid token returns 401")
    void getAllClientsWithInvalidTokenReturns401() throws Exception {
      mockMvc.perform(get("/api/oidc/clients")
              .header("Authorization", "Bearer invalid.token.here"))
          .andExpect(status().isUnauthorized());
    }
  }

  @Nested
  @DisplayName("GET /api/oidc/clients/{id}")
  class GetClient {

    @Test
    @DisplayName("with admin token returns client")
    void getClientAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(get("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.clientId.value").value("test-client"))
          .andExpect(jsonPath("$.clientName.value").value("Test Client"));
    }

    @Test
    @DisplayName("with non-existent id returns 404")
    void getClientWithNonExistentIdReturns404() throws Exception {
      String adminToken = jwtService.generateToken(admin);
      String nonExistentId = UUID.randomUUID().toString();

      mockMvc.perform(get("/api/oidc/clients/{id}", nonExistentId)
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("with invalid id format returns 400")
    void getClientWithInvalidIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(get("/api/oidc/clients/{id}", "invalid-uuid")
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("without authentication returns 403")
    void getClientWithoutAuthReturns403() throws Exception {
      mockMvc.perform(get("/api/oidc/clients/{id}", existingClient.getId()))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void getClientAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      mockMvc.perform(get("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + userToken))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  @DisplayName("POST /api/oidc/clients")
  class CreateClient {

    @Test
    @DisplayName("with admin token creates client and returns secret")
    void createClientAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = CreateOidcClientRequest.builder()
          .clientId("new-client")
          .clientName("New Client")
          .grantTypes(Set.of("authorization_code"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("https://newclient.com/callback"))
          .postLogoutRedirectUris(Set.of("https://newclient.com/logout"))
          .scopes(Set.of("openid", "profile"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.client").exists())
          .andExpect(jsonPath("$.client.clientId.value").value("new-client"))
          .andExpect(jsonPath("$.clientSecret").exists())
          .andExpect(jsonPath("$.message").value("Store the client secret securely. It will not be shown again."));
    }

    @Test
    @DisplayName("with duplicate client id returns 400")
    void createClientWithDuplicateIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = CreateOidcClientRequest.builder()
          .clientId("test-client")
          .clientName("Duplicate Client")
          .grantTypes(Set.of("authorization_code"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("https://duplicate.com/callback"))
          .postLogoutRedirectUris(Set.of("https://duplicate.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("with invalid redirect uri returns 400")
    void createClientWithInvalidRedirectUriReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = CreateOidcClientRequest.builder()
          .clientId("invalid-client")
          .clientName("Invalid Client")
          .grantTypes(Set.of("authorization_code"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("http://example.com/callback"))
          .postLogoutRedirectUris(Set.of("https://example.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("with invalid grant type returns 400")
    void createClientWithInvalidGrantTypeReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = CreateOidcClientRequest.builder()
          .clientId("invalid-client")
          .clientName("Invalid Client")
          .grantTypes(Set.of("invalid_grant_type"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("https://example.com/callback"))
          .postLogoutRedirectUris(Set.of("https://example.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("without authentication returns 403")
    void createClientWithoutAuthReturns403() throws Exception {
      var request = CreateOidcClientRequest.builder()
          .clientId("new-client")
          .clientName("New Client")
          .grantTypes(Set.of("authorization_code"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("https://newclient.com/callback"))
          .postLogoutRedirectUris(Set.of("https://newclient.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void createClientAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      var request = CreateOidcClientRequest.builder()
          .clientId("new-client")
          .clientName("New Client")
          .grantTypes(Set.of("authorization_code"))
          .authenticationMethods(Set.of("client_secret_basic"))
          .redirectUris(Set.of("https://newclient.com/callback"))
          .postLogoutRedirectUris(Set.of("https://newclient.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(post("/api/oidc/clients")
              .header("Authorization", "Bearer " + userToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  @DisplayName("PUT /api/oidc/clients/{id}")
  class UpdateClient {

    @Test
    @DisplayName("with admin token updates client")
    void updateClientAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = UpdateOidcClientRequest.builder()
          .clientName("Updated Client Name")
          .grantTypes(Set.of("authorization_code", "client_credentials"))
          .redirectUris(Set.of("https://updated.com/callback"))
          .postLogoutRedirectUris(Set.of("https://updated.com/logout"))
          .scopes(Set.of("openid", "email"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(put("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.clientName.value").value("Updated Client Name"));
    }

    @Test
    @DisplayName("with non-existent id returns 400")
    void updateClientWithNonExistentIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);
      String nonExistentId = UUID.randomUUID().toString();

      var request = UpdateOidcClientRequest.builder()
          .clientName("Updated Client Name")
          .grantTypes(Set.of("authorization_code"))
          .redirectUris(Set.of("https://updated.com/callback"))
          .postLogoutRedirectUris(Set.of("https://updated.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(put("/api/oidc/clients/{id}", nonExistentId)
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("with invalid redirect uri returns 400")
    void updateClientWithInvalidRedirectUriReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      var request = UpdateOidcClientRequest.builder()
          .clientName("Updated Client Name")
          .grantTypes(Set.of("authorization_code"))
          .redirectUris(Set.of("http://example.com/callback"))
          .postLogoutRedirectUris(Set.of("https://example.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(put("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("without authentication returns 403")
    void updateClientWithoutAuthReturns403() throws Exception {
      var request = UpdateOidcClientRequest.builder()
          .clientName("Updated Client Name")
          .grantTypes(Set.of("authorization_code"))
          .redirectUris(Set.of("https://updated.com/callback"))
          .postLogoutRedirectUris(Set.of("https://updated.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(put("/api/oidc/clients/{id}", existingClient.getId())
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void updateClientAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      var request = UpdateOidcClientRequest.builder()
          .clientName("Updated Client Name")
          .grantTypes(Set.of("authorization_code"))
          .redirectUris(Set.of("https://updated.com/callback"))
          .postLogoutRedirectUris(Set.of("https://updated.com/logout"))
          .scopes(Set.of("openid"))
          .tokenSettings(TokenSettings.defaults())
          .clientSettings(ClientSettings.defaults())
          .build();

      mockMvc.perform(put("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + userToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  @DisplayName("DELETE /api/oidc/clients/{id}")
  class DeleteClient {

    @Test
    @DisplayName("with admin token deletes client")
    void deleteClientAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(delete("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.message").value("Client deleted successfully"));

      mockMvc.perform(get("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("with non-existent id returns 400")
    void deleteClientWithNonExistentIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);
      String nonExistentId = UUID.randomUUID().toString();

      mockMvc.perform(delete("/api/oidc/clients/{id}", nonExistentId)
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("with invalid id format returns 400")
    void deleteClientWithInvalidIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(delete("/api/oidc/clients/{id}", "invalid-uuid")
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("without authentication returns 403")
    void deleteClientWithoutAuthReturns403() throws Exception {
      mockMvc.perform(delete("/api/oidc/clients/{id}", existingClient.getId()))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void deleteClientAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      mockMvc.perform(delete("/api/oidc/clients/{id}", existingClient.getId())
              .header("Authorization", "Bearer " + userToken))
          .andExpect(status().isForbidden());
    }
  }

  @Nested
  @DisplayName("POST /api/oidc/clients/{id}/regenerate-secret")
  class RegenerateSecret {

    @Test
    @DisplayName("with admin token regenerates secret")
    void regenerateSecretAsAdmin() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(post("/api/oidc/clients/{id}/regenerate-secret", existingClient.getId())
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.client").exists())
          .andExpect(jsonPath("$.clientSecret").exists())
          .andExpect(jsonPath("$.message").value("Store the new client secret securely. It will not be shown again."));
    }

    @Test
    @DisplayName("with non-existent id returns 400")
    void regenerateSecretWithNonExistentIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);
      String nonExistentId = UUID.randomUUID().toString();

      mockMvc.perform(post("/api/oidc/clients/{id}/regenerate-secret", nonExistentId)
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("with invalid id format returns 400")
    void regenerateSecretWithInvalidIdReturns400() throws Exception {
      String adminToken = jwtService.generateToken(admin);

      mockMvc.perform(post("/api/oidc/clients/{id}/regenerate-secret", "invalid-uuid")
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("without authentication returns 403")
    void regenerateSecretWithoutAuthReturns403() throws Exception {
      mockMvc.perform(post("/api/oidc/clients/{id}/regenerate-secret", existingClient.getId()))
          .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("with non-admin token returns 403")
    void regenerateSecretAsNonAdminReturns403() throws Exception {
      String userToken = jwtService.generateToken(user);

      mockMvc.perform(post("/api/oidc/clients/{id}/regenerate-secret", existingClient.getId())
              .header("Authorization", "Bearer " + userToken))
          .andExpect(status().isForbidden());
    }
  }
}