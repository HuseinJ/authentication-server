package com.hjusic.auth.domain.oidc.api;

import com.hjusic.auth.domain.oidc.infrastructure.OAuth2AuthorizationJpaRepository;
import com.hjusic.auth.domain.oidc.infrastructure.OidcClientDatabaseEntity;
import jakarta.persistence.EntityManager;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class OidcAuthenticationFlowIntegrationTest extends OidcClientApiIntegrationTestBase {

  private static final String TEST_CLIENT_ID = "oidc-test-client";
  private static final String TEST_CLIENT_SECRET = "test-secret-12345";
  private static final String TEST_REDIRECT_URI = "https://example.com/callback";

  @Autowired
  private RegisteredClientRepository registeredClientRepository;

  @Autowired
  private EntityManager entityManager;

  @Autowired
  private PlatformTransactionManager transactionManager;

  @Autowired
  private OAuth2AuthorizationJpaRepository authorizationRepository;

  @BeforeEach
  void setUpOidcTestClient() {
    // Delete any existing test client first
    oidcClientRepository.findByClientId(TEST_CLIENT_ID)
        .ifPresent(oidcClientRepository::delete);
    if (oidcClientRepository.findByClientId(TEST_CLIENT_ID).isEmpty()) {
      OidcClientDatabaseEntity oidcTestClient = OidcClientDatabaseEntity.builder()
          .id(UUID.randomUUID().toString())
          .clientId(TEST_CLIENT_ID)
          .clientSecret(passwordEncoder.encode(TEST_CLIENT_SECRET))
          .clientName("OIDC Test Client")
          .grantTypes(Set.of("authorization_code", "refresh_token"))
          .authenticationMethods(Set.of("client_secret_basic", "client_secret_post"))
          .redirectUris(Set.of(TEST_REDIRECT_URI))
          .postLogoutRedirectUris(Set.of("https://example.com/logout"))
          .scopes(Set.of("openid", "profile", "email"))
          .accessTokenTimeToLiveSeconds(3600L)
          .refreshTokenTimeToLiveSeconds(86400L)
          .authorizationCodeTimeToLiveSeconds(300L)
          .reuseRefreshTokens(false)
          .requireProofKey(false)
          .requireAuthorizationConsent(false)
          .clientIdIssuedAt(Instant.now())
          .build();
      oidcClientRepository.saveAndFlush(oidcTestClient);
    }



    // Force the persistence context to sync with DB
    entityManager.clear();
  }

  @Test
  @DisplayName("Full OIDC flow succeeds with valid client")
  @WithMockUser(username = "user@example.com", authorities = {"ROLE_GUEST"})
  @DirtiesContext
  void fullOidcFlowSucceeds() throws Exception {
    // Verify client exists via JPA repo (direct DB check)
    var dbClient = oidcClientRepository.findByClientId(TEST_CLIENT_ID);
    assertThat(dbClient).as("Client must exist in DB").isPresent();

    // Verify via RegisteredClientRepository
    RegisteredClient client = registeredClientRepository.findByClientId(TEST_CLIENT_ID);
    assertThat(client).as("Client must be findable via RegisteredClientRepository").isNotNull();

    // Step 1: Request Authorization Code (in its own transaction)
    AtomicReference<String> codeRef = new AtomicReference<>();

    TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);
    txTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

    txTemplate.execute(status -> {
      try {
        MvcResult authResult = mockMvc.perform(get("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", TEST_CLIENT_ID)
                .queryParam("scope", "openid profile")
                .queryParam("redirect_uri", TEST_REDIRECT_URI)
                .queryParam("state", "test-state"))
            .andDo(print())
            .andExpect(status().is3xxRedirection())
            .andReturn();

        String location = authResult.getResponse().getHeader("Location");
        assertThat(location).startsWith(TEST_REDIRECT_URI);

        String code = UriComponentsBuilder.fromUriString(location)
            .build()
            .getQueryParams()
            .getFirst("code");

        assertThat(code).isNotBlank();
        codeRef.set(code);

      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return null;
    });

    // Verify the authorization was persisted
    System.out.println("=== Verifying DB state after Step 1 ===");
    authorizationRepository.findAll().forEach(auth -> {
      System.out.println("Authorization ID: " + auth.getId());
      System.out.println("Code: " + auth.getAuthorizationCodeValue());
    });

    // Step 2: Exchange authorization code for tokens (in its own transaction)
    String code = codeRef.get();
    String clientAuth = "Basic " + Base64.getEncoder()
        .encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes());

    txTemplate.execute(status -> {
      try {
        mockMvc.perform(post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("Authorization", clientAuth)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", TEST_REDIRECT_URI))
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.id_token").exists());
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return null;
    });
  }

  @Test
  @DisplayName("Discovery endpoint works")
  void discoveryEndpointWorks() throws Exception {
    mockMvc.perform(get("/.well-known/openid-configuration"))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.issuer").exists());
  }

  @Test
  @DisplayName("JWKS endpoint works")
  void jwksEndpointWorks() throws Exception {
    mockMvc.perform(get("/oauth2/jwks"))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.keys").isArray());
  }
}