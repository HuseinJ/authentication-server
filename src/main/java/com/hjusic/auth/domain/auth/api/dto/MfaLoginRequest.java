package com.hjusic.auth.domain.auth.api.dto;

import lombok.Data;

@Data
public class MfaLoginRequest {
  private String mfaToken;
  private String code;
}
