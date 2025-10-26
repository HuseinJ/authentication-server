package com.hjusic.auth.domain.user.api.dto;

import lombok.Data;

@Data
public class InitiateResetPasswordRequest {
  private String username;
}