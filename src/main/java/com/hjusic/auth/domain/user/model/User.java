package com.hjusic.auth.domain.user.model;

import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Data
@SuperBuilder
@EqualsAndHashCode(of = {"username", "email"})
public abstract class User {

  private Username username;
  private Email email;
  private Set<String> roles;

  public abstract String getUserType();
}
