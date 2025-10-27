package com.hjusic.auth.domain.user.api.dto;

import com.hjusic.auth.domain.role.infrastructure.RoleName;
import java.util.Set;
import lombok.Data;

@Data
public class UpdateRoleRequest {
  private Set<RoleName> roles;
}
