package com.hjusic.auth.domain.role.model;

import java.util.List;

public interface Roles {

  List<Role> findAll();
  List<Role> findRolesOfUser(String username);

}
