package com.hjusic.auth.domain.role.model;

import com.hjusic.auth.domain.role.infrastructure.RoleName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@AllArgsConstructor(access = lombok.AccessLevel.PRIVATE)
@EqualsAndHashCode(of = "name")
public class Role {

  private final RoleName name;

  public static Role of(RoleName name) {
    return new Role(name);
  }
}
