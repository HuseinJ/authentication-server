package com.hjusic.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

@Configuration
public class OAuthConfig {

  @Value("${auth.ui}")
  private String uiUrl;

  @Value("${jwt.private-key}")
  private String privateKeyString;

  @Value("${jwt.public-key}")
  private String publicKeyString;

  @Value("${jwt.issuer}")
  private String issuer;

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {

    // Configure OAuth2 Authorization Server
    http
        .securityMatcher("/oauth2/**", "/.well-known/**")
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/.well-known/**").permitAll()
            .anyRequest().authenticated()
        )
        .with(new OAuth2AuthorizationServerConfigurer(), oauth2 ->
            oauth2.oidc(Customizer.withDefaults())
        )
        .exceptionHandling(exceptions -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint(uiUrl + "/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
        );

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/login", "/oauth2/authorize")
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        )
        // Disable form login since we're using external UI
        .formLogin(form -> form
            .loginPage(uiUrl + "/login")
        );

    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    return new JdbcRegisteredClientRepository(jdbcTemplate);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAPublicKey publicKey = loadPublicKey();
    RSAPrivateKey privateKey = loadPrivateKey();

    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private RSAPrivateKey loadPrivateKey() {
    try {
      String privateKeyPEM = privateKeyString
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load private key", e);
    }
  }

  private RSAPublicKey loadPublicKey() {
    try {
      String publicKeyPEM = publicKeyString
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load public key", e);
    }
  }

  /**
   * JWT Decoder - Uses your existing public key for validation
   */
  @Bean
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(loadPublicKey()).build();
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
        .issuer(issuer)
        .build();
  }

}
