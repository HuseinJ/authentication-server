package com.hjusic.auth.domain.user.api;

import com.hjusic.auth.domain.user.model.Users;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserInfoEmailsController {

  private final Users users;

  @GetMapping("/userinfo/emails")
  public ResponseEntity<?> userinfoEmails(
      @AuthenticationPrincipal Jwt jwt) {
    if (jwt == null) {
      return ResponseEntity.status(401).build();
    }

    String username = jwt.getSubject();
    var result = users.findByUsername(username);
    if (result.isLeft()) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(List.of(
        Map.of(
            "email", result.get().getEmail().getValue(),
            "primary", true,
            "verified", true
        )
    ));
  }
}
