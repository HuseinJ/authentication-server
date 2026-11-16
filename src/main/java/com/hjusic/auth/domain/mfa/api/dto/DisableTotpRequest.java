package com.hjusic.auth.domain.mfa.api.dto;

import lombok.Data;

@Data
public class DisableTotpRequest {
  private String password;
  private String code;
}
