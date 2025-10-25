package com.hjusic.auth.domain.user.api.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserRequest {
  private String username;
  private String email;
  private String password;
  private List<String> roles;
}
