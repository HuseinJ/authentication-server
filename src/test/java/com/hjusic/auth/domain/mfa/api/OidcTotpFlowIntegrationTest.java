package com.hjusic.auth.domain.mfa.api;

import static com.hjusic.auth.domain.mfa.TotpTestSupport.codeAt;
import static com.hjusic.auth.domain.mfa.TotpTestSupport.currentCode;
import static com.hjusic.auth.domain.mfa.TotpTestSupport.enroll;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.hjusic.auth.TestPasswordEncoderConfig;
import com.hjusic.auth.config.AuthorizationServerConfig;
import com.hjusic.auth.domain.mfa.MutableClock;
import com.hjusic.auth.domain.oidc.api.OidcClientApiIntegrationTestBase;
import com.hjusic.auth.domain.oidc.infrastructure.OidcClientDatabaseEntity;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Browser-style OIDC login (authorization code flow) for a user with TOTP enabled:
 * password form login, then the TOTP step, then the authorization code is issued.
 */
@Import({TestPasswordEncoderConfig.class, MutableClock.Config.class})
class OidcTotpFlowIntegrationTest extends OidcClientApiIntegrationTestBase {

  private static final String CLIENT_ID = "oidc-mfa-client";
  private static final String CLIENT_SECRET = "mfa-client-secret";
  private static final String REDIRECT_URI = "https://example.com/callback";
  private static final String UI = "http://localhost:3000";
  private static final String MFA_PAGE =
      UI + "/login/mfa?flow=oidc&factor.type=totp&factor.reason=missing";

  @Autowired
  private MutableClock clock;

  private String secret;

  @BeforeEach
  void setUp() throws Exception {
    clock.set(MutableClock.DEFAULT_START);
    oidcClientRepository.saveAndFlush(OidcClientDatabaseEntity.builder()
        .id(UUID.randomUUID().toString())
        .clientId(CLIENT_ID)
        .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
        .clientName("OIDC MFA Client")
        .grantTypes(Set.of("authorization_code", "refresh_token"))
        .authenticationMethods(Set.of("client_secret_basic"))
        .redirectUris(Set.of(REDIRECT_URI))
        .postLogoutRedirectUris(Set.of("https://example.com/logout"))
        .scopes(Set.of("openid", "profile"))
        .accessTokenTimeToLiveSeconds(3600L)
        .refreshTokenTimeToLiveSeconds(86400L)
        .authorizationCodeTimeToLiveSeconds(300L)
        .reuseRefreshTokens(false)
        .requireProofKey(false)
        .requireAuthorizationConsent(false)
        .clientIdIssuedAt(Instant.now())
        .build());

    var guest = userRepository.findByUsername("user").orElseThrow();
    secret = enroll(mockMvc, clock, tokenIssuer.generateToken(guest));
  }

  @Test
  @DisplayName("password login is followed by the TOTP step before a code is issued")
  void fullFlowWithTotp() throws Exception {
    MockHttpSession session = startFlow();

    // Password step: Spring resumes the saved authorize request...
    String resume = passwordLogin(session);
    assertThat(resume).contains("/oauth2/authorize").contains("continue");

    // ...which is denied for the missing FACTOR_TOTP and redirected to the UI's TOTP page.
    String mfaPage = redirectOf(get(URI.create(resume)).session(session));
    assertThat(mfaPage).isEqualTo(MFA_PAGE);

    // TOTP step on the same session: resumes the authorize request again.
    String resumeAfterTotp = redirectOf(post(AuthorizationServerConfig.TOTP_LOGIN_URL)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("code", currentCode(clock, secret))
        .session(session));
    assertThat(resumeAfterTotp).contains("/oauth2/authorize").contains("continue");

    // Now both factors are present: the client receives its authorization code.
    String callback = redirectOf(get(URI.create(resumeAfterTotp)).session(session));
    assertThat(callback).startsWith(REDIRECT_URI);
    String code = UriComponentsBuilder.fromUriString(callback).build().getQueryParams()
        .getFirst("code");
    assertThat(code).isNotBlank();

    mockMvc.perform(post("/oauth2/token")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()))
            .param("grant_type", "authorization_code")
            .param("code", code)
            .param("redirect_uri", REDIRECT_URI))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.access_token").exists())
        .andExpect(jsonPath("$.id_token").exists());
  }

  @Test
  @DisplayName("a wrong TOTP code redirects back with an error and issues no code")
  void wrongCodeIsRejected() throws Exception {
    MockHttpSession session = startFlow();
    passwordLogin(session);

    String failure = redirectOf(post(AuthorizationServerConfig.TOTP_LOGIN_URL)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("code", codeAt(clock, secret, 10))
        .session(session));
    assertThat(failure).isEqualTo(UI + "/login/mfa?flow=oidc&factor.type=totp&error=true");

    assertThat(redirectOf(authorize().session(session)))
        .isEqualTo(MFA_PAGE);
  }

  @Test
  @DisplayName("the TOTP step cannot replace the password step")
  void totpWithoutPasswordIsRejected() throws Exception {
    MockHttpSession session = startFlow();

    String failure = redirectOf(post(AuthorizationServerConfig.TOTP_LOGIN_URL)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("code", currentCode(clock, secret))
        .session(session));
    assertThat(failure).endsWith("&error=true");

    assertThat(redirectOf(authorize().session(session)))
        .isEqualTo(UI + "/login?flow=oidc");
  }

  private MockHttpSession startFlow() throws Exception {
    MvcResult result = mockMvc.perform(authorize())
        .andExpect(status().is3xxRedirection())
        .andReturn();
    assertThat(result.getResponse().getHeader("Location")).isEqualTo(UI + "/login?flow=oidc");
    return (MockHttpSession) result.getRequest().getSession();
  }

  private String passwordLogin(MockHttpSession session) throws Exception {
    return redirectOf(post("/oauth2/login")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .param("username", "user")
        .param("password", "password123")
        .session(session));
  }

  private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorize() {
    return get("/oauth2/authorize")
        .queryParam("response_type", "code")
        .queryParam("client_id", CLIENT_ID)
        .queryParam("scope", "openid profile")
        .queryParam("redirect_uri", REDIRECT_URI)
        .queryParam("state", "mfa-state");
  }

  private String redirectOf(
      org.springframework.test.web.servlet.RequestBuilder request) throws Exception {
    MvcResult result = mockMvc.perform(request)
        .andExpect(status().is3xxRedirection())
        .andReturn();
    return result.getResponse().getHeader("Location");
  }
}
