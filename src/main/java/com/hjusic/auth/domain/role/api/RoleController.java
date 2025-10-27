package com.hjusic.auth.domain.role.api;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.role.model.Roles;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/role")
@RequiredArgsConstructor
public class RoleController {

  private final Roles roles;
  private final Auth auth;

  @GetMapping
  @RequestMapping("/all")
  public Collection<Role> getAllRoles() {
    return roles.findAll();
  }

  @GetMapping
  @RequestMapping
  public Collection<Role> getRoles() {
    var user = auth.findLoggedInUser();
    if(user.isLeft()) {
      throw new IllegalStateException("User is not authenticated");
    }
    return roles.findRolesOfUser(user.get().getUsername().getValue());
  }

}
