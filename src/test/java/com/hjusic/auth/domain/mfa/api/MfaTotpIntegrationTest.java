package com.hjusic.auth.domain.mfa.api;

import static com.hjusic.auth.domain.mfa.TotpTestSupport.codeAt;
import static com.hjusic.auth.domain.mfa.TotpTestSupport.currentCode;
import static com.hjusic.auth.domain.mfa.TotpTestSupport.enroll;
import static com.hjusic.auth.domain.mfa.TotpTestSupport.json;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.hjusic.auth.TestPasswordEncoderConfig;
import com.hjusic.auth.domain.mfa.MutableClock;
import com.hjusic.auth.domain.mfa.infrastructure.MfaChallengeDatabaseRepository;
import com.hjusic.auth.domain.mfa.infrastructure.TotpCredentialDatabaseRepository;
import com.hjusic.auth.domain.user.api.UserApiIntegrationTestBase;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

@Import({TestPasswordEncoderConfig.class, MutableClock.Config.class})
class MfaTotpIntegrationTest extends UserApiIntegrationTestBase {

  @Autowired
  private MutableClock clock;

  @Autowired
  private TotpCredentialDatabaseRepository totpRepository;

  @Autowired
  private MfaChallengeDatabaseRepository challengeRepository;

  private String userToken;
  private String adminToken;

  @BeforeEach
  void setUp() {
    clock.set(MutableClock.DEFAULT_START);
    challengeRepository.deleteAll();
    userToken = tokenIssuer.generateToken(user);
    adminToken = tokenIssuer.generateToken(admin);
  }

  @Nested
  @DisplayName("Enrollment")
  class Enrollment {

    @Test
    @DisplayName("start returns a Base32 secret and an otpauth URI for the QR code")
    void startReturnsSecretAndUri() throws Exception {
      mockMvc.perform(post("/api/mfa/totp").header("Authorization", "Bearer " + userToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.secret").value(org.hamcrest.Matchers.matchesPattern("[A-Z2-7]{32}")))
          .andExpect(jsonPath("$.otpauthUri").value(org.hamcrest.Matchers.startsWith(
              "otpauth://totp/Test%20Issuer:user?secret=")));
    }

    @Test
    @DisplayName("requires authentication")
    void requiresAuthentication() throws Exception {
      mockMvc.perform(post("/api/mfa/totp")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("TOTP only counts as enrolled after confirmation")
    void confirmationActivatesFactor() throws Exception {
      factorsOf(userToken).andExpect(jsonPath("$.factors").isEmpty());

      String body = mockMvc.perform(post("/api/mfa/totp")
              .header("Authorization", "Bearer " + userToken))
          .andReturn().getResponse().getContentAsString();
      String secret = json(body).get("secret").asText();

      // Pending enrollment: not a factor yet, password login still issues tokens directly.
      factorsOf(userToken).andExpect(jsonPath("$.factors").isEmpty());
      passwordLogin().andExpect(jsonPath("$.token").exists());

      mockMvc.perform(post("/api/mfa/totp/confirm")
              .header("Authorization", "Bearer " + userToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"code\":\"" + currentCode(clock, secret) + "\"}"))
          .andExpect(status().isOk());

      factorsOf(userToken).andExpect(jsonPath("$.factors[0]").value("totp"));
    }

    @Test
    @DisplayName("confirm rejects a wrong code")
    void confirmRejectsWrongCode() throws Exception {
      String body = mockMvc.perform(post("/api/mfa/totp")
              .header("Authorization", "Bearer " + userToken))
          .andReturn().getResponse().getContentAsString();
      String secret = json(body).get("secret").asText();

      mockMvc.perform(post("/api/mfa/totp/confirm")
              .header("Authorization", "Bearer " + userToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"code\":\"" + codeAt(clock, secret, 5) + "\"}"))
          .andExpect(status().isBadRequest());

      factorsOf(userToken).andExpect(jsonPath("$.factors").isEmpty());
    }

    @Test
    @DisplayName("an active authenticator cannot be replaced without disabling it first")
    void cannotReEnrollWhileActive() throws Exception {
      enroll(mockMvc, clock, userToken);

      mockMvc.perform(post("/api/mfa/totp").header("Authorization", "Bearer " + userToken))
          .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("the secret is stored encrypted, never in plain text")
    void secretIsEncryptedAtRest() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);

      var stored = totpRepository.findByUserUsername("user").orElseThrow();
      assertThat(stored.getEncryptedSecret()).doesNotContain(secret);
      assertThat(stored.getEncryptedSecret()).doesNotContainIgnoringCase(
          java.util.Base64.getEncoder().encodeToString(
              com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret.fromBase32(secret)
                  .getValue()));
    }
  }

  @Nested
  @DisplayName("REST login with TOTP")
  class RestLogin {

    @Test
    @DisplayName("password login returns an MFA challenge instead of tokens")
    void passwordLoginReturnsChallenge() throws Exception {
      enroll(mockMvc, clock, userToken);

      passwordLogin()
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.mfaRequired").value(true))
          .andExpect(jsonPath("$.mfaToken").isNotEmpty())
          .andExpect(jsonPath("$.factors[0]").value("totp"))
          .andExpect(jsonPath("$.expiresIn").value(300))
          .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    @DisplayName("challenge + valid code yields tokens")
    void challengePlusCodeYieldsTokens() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);

      totpLogin(challenge(), currentCode(clock, secret))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.token").isNotEmpty())
          .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    @DisplayName("a challenge can only be redeemed once")
    void challengeIsSingleUse() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);
      String challenge = challenge();

      totpLogin(challenge, currentCode(clock, secret)).andExpect(status().isOk());
      clock.advance(Duration.ofSeconds(30));
      totpLogin(challenge, currentCode(clock, secret))
          .andExpect(status().isUnauthorized())
          .andExpect(jsonPath("$.mfaToken").doesNotExist());
    }

    @Test
    @DisplayName("an expired or unknown challenge is rejected")
    void expiredChallengeRejected() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);
      String challenge = challenge();

      totpLogin("not-a-real-token", currentCode(clock, secret))
          .andExpect(status().isUnauthorized());

      clock.advance(Duration.ofMinutes(6));
      totpLogin(challenge, currentCode(clock, secret)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a used code cannot be replayed; a wrong code returns a fresh challenge")
    void replayIsRejectedWithRetryChallenge() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);
      String code = currentCode(clock, secret);
      totpLogin(challenge(), code).andExpect(status().isOk());

      String body = totpLogin(challenge(), code)
          .andExpect(status().isUnauthorized())
          .andExpect(jsonPath("$.error").value("Invalid verification code"))
          .andReturn().getResponse().getContentAsString();
      String retryChallenge = json(body).get("mfaToken").asText();

      clock.advance(Duration.ofSeconds(30));
      totpLogin(retryChallenge, currentCode(clock, secret)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("too many wrong codes lock TOTP temporarily, even for valid codes")
    void lockoutAfterRepeatedFailures() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);
      String wrongCode = codeAt(clock, secret, 10);

      String challenge = challenge();
      for (int attempt = 1; attempt < 5; attempt++) {
        String body = totpLogin(challenge, wrongCode)
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();
        challenge = json(body).get("mfaToken").asText();
      }
      totpLogin(challenge, wrongCode).andExpect(status().isTooManyRequests());

      totpLogin(challenge(), currentCode(clock, secret)).andExpect(status().isTooManyRequests());

      clock.advance(Duration.ofMinutes(16));
      totpLogin(challenge(), currentCode(clock, secret)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("wrong password never reaches the TOTP step")
    void wrongPasswordStillFails() throws Exception {
      enroll(mockMvc, clock, userToken);

      mockMvc.perform(post("/api/auth/login")
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"username\":\"user\",\"password\":\"wrong\"}"))
          .andExpect(status().is4xxClientError())
          .andExpect(jsonPath("$.mfaToken").doesNotExist());
    }
  }

  @Nested
  @DisplayName("Disabling and resetting")
  class DisableAndReset {

    @Test
    @DisplayName("users disable TOTP with password + current code; login is password-only again")
    void userDisablesTotp() throws Exception {
      String secret = enroll(mockMvc, clock, userToken);

      disable("wrong-password", currentCode(clock, secret)).andExpect(status().isBadRequest());
      disable("password123", codeAt(clock, secret, 5)).andExpect(status().isBadRequest());
      factorsOf(userToken).andExpect(jsonPath("$.factors[0]").value("totp"));

      clock.advance(Duration.ofSeconds(30));
      disable("password123", currentCode(clock, secret)).andExpect(status().isOk());

      factorsOf(userToken).andExpect(jsonPath("$.factors").isEmpty());
      passwordLogin().andExpect(jsonPath("$.token").exists());
      assertThat(totpRepository.findByUserUsername("user")).isEmpty();
    }

    @Test
    @DisplayName("admins can reset a user's TOTP; other users cannot")
    void adminResetsTotp() throws Exception {
      enroll(mockMvc, clock, userToken);

      mockMvc.perform(delete("/api/mfa/users/user/totp")
              .header("Authorization", "Bearer " + userToken))
          .andExpect(status().isForbidden());

      mockMvc.perform(delete("/api/mfa/users/user/totp")
              .header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk());

      factorsOf(userToken).andExpect(jsonPath("$.factors").isEmpty());
    }

    @Test
    @DisplayName("deleting a user removes their TOTP credential")
    void deletingUserCascades() throws Exception {
      enroll(mockMvc, clock, userToken);

      mockMvc.perform(delete("/api/user/user").header("Authorization", "Bearer " + adminToken))
          .andExpect(status().isOk());

      assertThat(totpRepository.count()).isZero();
    }
  }

  private ResultActions factorsOf(String token) throws Exception {
    return mockMvc.perform(get("/api/mfa").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
  }

  private ResultActions passwordLogin() throws Exception {
    return mockMvc.perform(post("/api/auth/login")
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"username\":\"user\",\"password\":\"password123\"}"));
  }

  private String challenge() throws Exception {
    String body = passwordLogin()
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    JsonNode json = json(body);
    assertThat(json.get("mfaRequired").asBoolean()).isTrue();
    return json.get("mfaToken").asText();
  }

  private ResultActions totpLogin(String mfaToken, String code) throws Exception {
    return mockMvc.perform(post("/api/auth/login/mfa/totp")
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"mfaToken\":\"" + mfaToken + "\",\"code\":\"" + code + "\"}"));
  }

  private ResultActions disable(String password, String code) throws Exception {
    return mockMvc.perform(delete("/api/mfa/totp")
        .header("Authorization", "Bearer " + userToken)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"password\":\"" + password + "\",\"code\":\"" + code + "\"}"));
  }
}
