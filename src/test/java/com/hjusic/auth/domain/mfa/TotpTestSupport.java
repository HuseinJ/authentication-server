package com.hjusic.auth.domain.mfa;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpAlgorithm;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import java.time.Duration;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** Drives TOTP enrollment through the public API, like a real client would. */
public final class TotpTestSupport {

  private static final ObjectMapper JSON = new ObjectMapper();

  private TotpTestSupport() {
  }

  /** Code the user's authenticator app shows at the clock's current time (+ offset steps). */
  public static String codeAt(MutableClock clock, String base32Secret, int stepOffset) {
    long step = TotpAlgorithm.timeStep(clock.instant()) + stepOffset;
    return TotpAlgorithm.generate(TotpSecret.fromBase32(base32Secret), step);
  }

  public static String currentCode(MutableClock clock, String base32Secret) {
    return codeAt(clock, base32Secret, 0);
  }

  /** Starts and confirms TOTP; returns the Base32 secret. Leaves the clock on a fresh step. */
  public static String enroll(MockMvc mockMvc, MutableClock clock, String bearerToken)
      throws Exception {
    String body = mockMvc.perform(post("/api/mfa/totp")
            .header("Authorization", "Bearer " + bearerToken))
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    String secret = JSON.readTree(body).get("secret").asText();

    mockMvc.perform(post("/api/mfa/totp/confirm")
            .header("Authorization", "Bearer " + bearerToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"code\":\"" + currentCode(clock, secret) + "\"}"))
        .andExpect(status().isOk());

    // The confirmation burned the current step; move on so the next code is usable.
    clock.advance(TotpAlgorithm.TIME_STEP);
    return secret;
  }

  public static JsonNode json(String body) throws Exception {
    return JSON.readTree(body);
  }

  public static Duration step() {
    return TotpAlgorithm.TIME_STEP;
  }
}
