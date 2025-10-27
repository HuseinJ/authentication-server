package com.hjusic.auth.domain.role.infrastructure;

import com.hjusic.auth.domain.role.model.Role;
import org.springframework.stereotype.Component;

@Component
public class RoleMapper {

  public Role toModelObject(RoleDatabaseEntity entity) {
    return Role.of(entity.getName());
  }

}
