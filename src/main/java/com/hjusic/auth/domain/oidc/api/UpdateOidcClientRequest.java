package com.hjusic.auth.domain.oidc.api;

import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateOidcClientRequest {

  private String clientName;
  private Set<String> grantTypes;
  private Set<String> redirectUris;
  private Set<String> postLogoutRedirectUris;
  private Set<String> scopes;
  private TokenSettings tokenSettings;
  private ClientSettings clientSettings;
}
