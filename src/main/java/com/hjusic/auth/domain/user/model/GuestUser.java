package com.hjusic.auth.domain.user.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

@Data
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class GuestUser extends User{
private final String USER_TYPE = "GUEST";

  @Override
  public String getUserType() {
    return "GUEST";
  }
}
