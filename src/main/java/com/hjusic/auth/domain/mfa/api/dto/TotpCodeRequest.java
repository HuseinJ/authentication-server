package com.hjusic.auth.domain.mfa.api.dto;

import lombok.Data;

@Data
public class TotpCodeRequest {
  private String code;
}
