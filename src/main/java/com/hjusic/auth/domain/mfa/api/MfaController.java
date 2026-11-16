package com.hjusic.auth.domain.mfa.api;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.mfa.api.dto.DisableTotpRequest;
import com.hjusic.auth.domain.mfa.api.dto.TotpCodeRequest;
import com.hjusic.auth.domain.mfa.application.ConfirmTotpEnrollment;
import com.hjusic.auth.domain.mfa.application.DisableTotp;
import com.hjusic.auth.domain.mfa.application.ResetTotp;
import com.hjusic.auth.domain.mfa.application.SecondFactorRegistry;
import com.hjusic.auth.domain.mfa.application.StartTotpEnrollment;
import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

  private final Auth auth;
  private final SecondFactorRegistry secondFactorRegistry;
  private final StartTotpEnrollment startTotpEnrollment;
  private final ConfirmTotpEnrollment confirmTotpEnrollment;
  private final DisableTotp disableTotp;
  private final ResetTotp resetTotp;

  /** Second factors the logged-in user has enrolled, e.g. {@code {"factors": ["totp"]}}. */
  @GetMapping
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> getFactors() {
    var user = auth.findLoggedInUser();
    if (user.isLeft()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    var factors = secondFactorRegistry.enrolledFactors(user.get().getUsername().getValue())
        .stream()
        .map(SecondFactorType::getId)
        .toList();
    return ResponseEntity.ok(Map.of("factors", factors));
  }

  /** Step 1 of enrollment: returns the secret and {@code otpauth://} URI (render as QR code). */
  @PostMapping("/totp")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> startTotpEnrollment() {
    return startTotpEnrollment.start().fold(
        MfaController::toErrorResponse,
        details -> ResponseEntity.ok(Map.of(
            "secret", details.secret(),
            "otpauthUri", details.otpAuthUri())));
  }

  /** Step 2 of enrollment: activates TOTP once the user enters a valid code from the app. */
  @PostMapping("/totp/confirm")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> confirmTotpEnrollment(@RequestBody TotpCodeRequest request) {
    return confirmTotpEnrollment.confirm(request.getCode()).fold(
        MfaController::toErrorResponse,
        ok -> ResponseEntity.ok(Map.of("message", "TOTP enabled")));
  }

  @DeleteMapping("/totp")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> disableTotp(@RequestBody DisableTotpRequest request) {
    return disableTotp.disable(request.getPassword(), request.getCode()).fold(
        MfaController::toErrorResponse,
        ok -> ResponseEntity.ok(Map.of("message", "TOTP disabled")));
  }

  /** Admin recovery, e.g. when a user lost their authenticator device. */
  @DeleteMapping("/users/{username}/totp")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<?> resetTotp(@PathVariable String username) {
    return resetTotp.reset(username).fold(
        MfaController::toErrorResponse,
        ok -> ResponseEntity.ok(Map.of("message", "TOTP reset for " + username)));
  }

  private static ResponseEntity<?> toErrorResponse(MfaError error) {
    HttpStatus status = switch (error.getCode()) {
      case UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED;
      case NOT_ENROLLED -> HttpStatus.NOT_FOUND;
      case ALREADY_ENROLLED -> HttpStatus.CONFLICT;
      case LOCKED -> HttpStatus.TOO_MANY_REQUESTS;
      case INVALID_CODE, VALIDATION_FAILED -> HttpStatus.BAD_REQUEST;
    };
    return ResponseEntity.status(status).body(Map.of("error", error.getMessage()));
  }
}
