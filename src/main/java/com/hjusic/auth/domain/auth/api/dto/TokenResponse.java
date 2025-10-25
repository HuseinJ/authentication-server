package com.hjusic.auth.domain.auth.api.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class TokenResponse {
  private final String type = "Bearer";
  private final String token;
  private final String refreshToken;
  private final Long expiresIn;
  private final Long refreshExpiresIn;
}
