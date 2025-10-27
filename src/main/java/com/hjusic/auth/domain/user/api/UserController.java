package com.hjusic.auth.domain.user.api;

import com.hjusic.auth.domain.user.api.dto.CompleteResetPasswordRequest;
import com.hjusic.auth.domain.user.api.dto.CreateUserRequest;
import com.hjusic.auth.domain.user.api.dto.InitiateResetPasswordRequest;
import com.hjusic.auth.domain.user.api.dto.UpdateRoleRequest;
import com.hjusic.auth.domain.user.application.CreateUser;
import com.hjusic.auth.domain.user.application.DeleteUser;
import com.hjusic.auth.domain.user.application.ResetPasswordProcess;
import com.hjusic.auth.domain.user.application.UpdateRoles;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.Users;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
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
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

  private final Users users;
  private final CreateUser createUser;
  private final DeleteUser deleteUser;
  private final ResetPasswordProcess resetPasswordProcess;
  private final UpdateRoles updateRoles;

  @GetMapping
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public Collection<User> getUsers() {
    return users.findAll();
  }

  @GetMapping("/{username}")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<?> getUser(@PathVariable String username) {
    return users.findByUsername(username)
        .fold(
            error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
            ResponseEntity::ok
        );
  }

  @PostMapping
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<?> createUser(@RequestBody CreateUserRequest createUserRequest) {

    return createUser.create(
        createUserRequest.getUsername(),
        createUserRequest.getEmail(),
        createUserRequest.getPassword(),
        Set.of()
    ).fold(
        error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
        ResponseEntity::ok
    );
  }

  @DeleteMapping("/{username}")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<?> deleteUser(@PathVariable String username) {

    return deleteUser.delete(username)
        .fold(
        error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
        ResponseEntity::ok
    );
  }

  @PostMapping("/roles/{username}")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<?> updateUserRoles(@PathVariable String username, @RequestBody
      UpdateRoleRequest updateRoleRequest) {

    return updateRoles.updateRoles(username, updateRoleRequest.getRoles()).fold(
        error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
        ResponseEntity::ok
    );
  }

  @PostMapping("/password-reset/initiate")
  public ResponseEntity<?> initiatePasswordReset(@RequestBody InitiateResetPasswordRequest request) {
    resetPasswordProcess.initiateResetPasswordProcess(request.getUsername());

    return ResponseEntity.ok(Map.of(
        "message", "If an account exists with that username, a password reset email has been sent"
    ));
  }

  @PostMapping("/password-reset/complete")
  public ResponseEntity<?> completePasswordReset(@RequestBody CompleteResetPasswordRequest request) {
    return resetPasswordProcess.completeResetPasswordProcess(
        request.getUsername(),
        request.getToken(),
        request.getNewPassword()
    ).fold(
        error -> ResponseEntity.badRequest().body(Map.of(
            "error", "Invalid or expired reset token"
        )),
        user -> ResponseEntity.ok(Map.of(
            "message", "Password successfully reset"
        ))
    );
  }

}
