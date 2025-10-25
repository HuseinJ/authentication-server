package com.hjusic.auth.domain.user.api;

import com.hjusic.auth.domain.user.api.dto.CreateUserRequest;
import com.hjusic.auth.domain.user.application.CreateUser;
import com.hjusic.auth.domain.user.application.DeleteUser;
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

}
