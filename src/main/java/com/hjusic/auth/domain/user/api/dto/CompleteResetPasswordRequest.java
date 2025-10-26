package com.hjusic.auth.domain.user.api.dto;

import lombok.Data;

@Data
public class CompleteResetPasswordRequest {
  private String username;
  private String token;
  private String newPassword;
}