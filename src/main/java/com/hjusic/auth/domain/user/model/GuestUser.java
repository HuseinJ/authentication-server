package com.hjusic.auth.domain.user.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class GuestUser extends User {

  private static final String USER_TYPE = "GUEST";

  @Override
  public String getUserType() {
    return USER_TYPE;
  }
}
