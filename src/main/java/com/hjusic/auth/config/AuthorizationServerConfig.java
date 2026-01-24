package com.hjusic.auth.config;

import com.hjusic.auth.domain.oidc.infrastructure.JpaOAuth2AuthorizationConsentService;
import com.hjusic.auth.domain.oidc.infrastructure.JpaOAuth2AuthorizationService;
import com.hjusic.auth.domain.oidc.infrastructure.JpaRegisteredClientRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
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
@RequiredArgsConstructor
public class AuthorizationServerConfig {

  @Value("${auth.issuer-uri}")
  private String issuerUri;

  @Value("${jwt.private-key}")
  private String privateKeyPem;

  @Value("${jwt.public-key}")
  private String publicKeyPem;

  private final OidcUserInfoMapper oidcUserInfoMapper;

  private final JpaRegisteredClientRepository jpaRegisteredClientRepository;

  private final JpaOAuth2AuthorizationService authorizationService;

  private final JpaOAuth2AuthorizationConsentService authorizationConsentService;

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    http.setSharedObject(RegisteredClientRepository.class, jpaRegisteredClientRepository);
    http.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
    http.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(oidc -> oidc
            .userInfoEndpoint(userInfo -> userInfo
                .userInfoMapper(oidcUserInfoMapper)
            )
        );

    http
        .exceptionHandling(exceptions -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/login", "/logout", "/error", "/css/**", "/js/**", "/images/**")
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().permitAll()
        )
        .formLogin(form -> form
            .loginPage("/login")
            .permitAll()
        )
        .logout(logout -> logout
            .logoutSuccessUrl("/login?logout")
            .permitAll()
        )
        .csrf(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAPublicKey publicKey = parsePublicKey(publicKeyPem);
    RSAPrivateKey privateKey = parsePrivateKey(privateKeyPem);

    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private RSAPublicKey parsePublicKey(String pem) {
    try {
      String publicKeyContent = pem
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(publicKeyContent);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse public key", e);
    }
  }

  private RSAPrivateKey parsePrivateKey(String pem) {
    try {
      String privateKeyContent = pem
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(privateKeyContent);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse private key", e);
    }
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
        .issuer(issuerUri)
        .authorizationEndpoint("/oauth2/authorize")
        .tokenEndpoint("/oauth2/token")
        .jwkSetEndpoint("/oauth2/jwks")
        .tokenRevocationEndpoint("/oauth2/revoke")
        .tokenIntrospectionEndpoint("/oauth2/introspect")
        .oidcUserInfoEndpoint("/userinfo")
        .oidcLogoutEndpoint("/connect/logout")
        .build();
  }
}