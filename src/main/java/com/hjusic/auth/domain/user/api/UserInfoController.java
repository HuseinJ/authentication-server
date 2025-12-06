package com.hjusic.auth.domain.user.api;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoController {

  @GetMapping("/userinfo")
  public Map<String, Object> userinfo(@AuthenticationPrincipal OidcUser user) {
    return Map.of(
        "sub", user.getSubject(),
        "email", user.getEmail(),
        "name", user.getFullName()
    );
  }
}
