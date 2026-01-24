package com.hjusic.auth.config;

import com.hjusic.auth.domain.user.model.Users;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class OidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

  private final Users users;

  @Override
  public OidcUserInfo apply(OidcUserInfoAuthenticationContext context) {
    var authorization = context.getAuthorization();
    var principalName = authorization.getPrincipalName();
    var scopes = authorization.getAuthorizedScopes();

    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", principalName);

    var userResult = users.findByUsername(principalName);
    if (userResult.isRight()) {
      var user = userResult.get();

      if (scopes.contains("profile")) {
        claims.put("preferred_username", user.getUsername().getValue());
        claims.put("name", user.getUsername().getValue());
      }

      if (scopes.contains("email")) {
        claims.put("email", user.getEmail().getValue());
        claims.put("email_verified", true);
      }

      if (scopes.contains("roles")) {
        claims.put("roles", user.getRoles().stream()
            .map(role -> role.getName().name())
            .toList());
      }
    }

    return new OidcUserInfo(claims);
  }
}