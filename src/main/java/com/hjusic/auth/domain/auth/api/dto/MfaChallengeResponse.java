package com.hjusic.auth.domain.auth.api.dto;

import java.util.List;

/**
 * Returned by {@code POST /api/auth/login} instead of tokens when the user has a second factor
 * enrolled. The client completes the login by sending {@code mfaToken} together with a code to
 * {@code POST /api/auth/login/mfa/{factor}}.
 *
 * @param factors   enrolled factors any one of which completes the login, e.g. {@code ["totp"]}
 * @param expiresIn seconds until {@code mfaToken} expires
 */
public record MfaChallengeResponse(boolean mfaRequired, String mfaToken, List<String> factors,
                                   long expiresIn) {

  public static MfaChallengeResponse of(String mfaToken, List<String> factors, long expiresIn) {
    return new MfaChallengeResponse(true, mfaToken, factors, expiresIn);
  }
}
