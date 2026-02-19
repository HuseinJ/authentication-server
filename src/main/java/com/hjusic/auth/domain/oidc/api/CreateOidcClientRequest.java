package com.hjusic.auth.domain.oidc.api;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateOidcClientRequest {

  private String clientId;
  private String clientName;
  private Set<String> grantTypes;
  private Set<String> authenticationMethods;
  private Set<String> redirectUris;
  private Set<String> postLogoutRedirectUris;
  private Set<String> scopes;
  private TokenSettingsRequest tokenSettings;
  private ClientSettingsRequest clientSettings;
}