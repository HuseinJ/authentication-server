package com.hjusic.auth.domain.oidc.infrastructure;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "oauth2_authorization_consents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@IdClass(OAuth2AuthorizationConsentEntity.AuthorizationConsentId.class)
public class OAuth2AuthorizationConsentEntity {

  @Id
  @Column(name = "registered_client_id", length = 100)
  private String registeredClientId;

  @Id
  @Column(name = "principal_name", length = 200)
  private String principalName;

  @Column(name = "authorities", length = 1000, nullable = false)
  private String authorities;

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  public static class AuthorizationConsentId implements Serializable {
    private String registeredClientId;
    private String principalName;

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      AuthorizationConsentId that = (AuthorizationConsentId) o;
      return Objects.equals(registeredClientId, that.registeredClientId)
          && Objects.equals(principalName, that.principalName);
    }

    @Override
    public int hashCode() {
      return Objects.hash(registeredClientId, principalName);
    }
  }
}