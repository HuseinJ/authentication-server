package com.hjusic.auth.domain.oidc.infrastructure;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "oauth_clients")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OidcClientDatabaseEntity {

  @Id
  @Column(name = "id", nullable = false, updatable = false)
  private String id;

  @Column(name = "client_id", nullable = false, unique = true)
  private String clientId;

  @Column(name = "client_secret", nullable = false)
  private String clientSecret;

  @Column(name = "client_name", nullable = false)
  private String clientName;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_grant_types",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id")
  )
  @Column(name = "grant_type")
  @Builder.Default
  private Set<String> grantTypes = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_authentication_methods",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id")
  )
  @Column(name = "authentication_method")
  @Builder.Default
  private Set<String> authenticationMethods = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id")
  )
  @Column(name = "redirect_uri", length = 1000)
  @Builder.Default
  private Set<String> redirectUris = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_post_logout_redirect_uris",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id")
  )
  @Column(name = "post_logout_redirect_uri", length = 1000)
  @Builder.Default
  private Set<String> postLogoutRedirectUris = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(
      name = "oauth_client_scopes",
      joinColumns = @JoinColumn(name = "client_id", referencedColumnName = "id")
  )
  @Column(name = "scope")
  @Builder.Default
  private Set<String> scopes = new HashSet<>();

  @Column(name = "access_token_ttl_seconds")
  private Long accessTokenTimeToLiveSeconds;

  @Column(name = "refresh_token_ttl_seconds")
  private Long refreshTokenTimeToLiveSeconds;

  @Column(name = "authorization_code_ttl_seconds")
  private Long authorizationCodeTimeToLiveSeconds;

  @Column(name = "reuse_refresh_tokens")
  private Boolean reuseRefreshTokens;

  @Column(name = "require_proof_key")
  private Boolean requireProofKey;

  @Column(name = "require_authorization_consent")
  private Boolean requireAuthorizationConsent;

  @Column(name = "client_id_issued_at", nullable = false)
  private Instant clientIdIssuedAt;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;

  @PrePersist
  protected void onCreate() {
    createdAt = Instant.now();
    updatedAt = Instant.now();
  }

  @PreUpdate
  protected void onUpdate() {
    updatedAt = Instant.now();
  }
}