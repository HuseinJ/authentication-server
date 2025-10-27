package com.hjusic.auth.domain.role.infrastructure;

import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.role.model.Roles;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleAppRepository implements Roles {

  private final RoleDatabaseRepository roleRepository;
  private final UserDatabaseRepository userRepository;
  private final RoleMapper roleMapper;

  @Override
  public List<Role> findAll() {
    return roleRepository.findAll().stream().map(roleMapper::toModelObject).toList();
  }

  @Override
  public List<Role> findRolesOfUser(String username) {
    var user = userRepository.findByUsername(username).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + username)
    );

    return roleRepository.findAllByUsersContains(user).stream().map(roleMapper::toModelObject)
        .toList();
  }
}
