package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.hjusic.auth.crypto.model.PasswordHasher;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.security.SecureRandom;
import java.util.Base64;

// A client secret (hash or plaintext) must never be serialized into an API response or onto the
// event bus. @JsonIgnoreType makes Jackson drop the property wherever a ClientSecret appears
// (OidcClient.clientSecret, OAuthClient*Event.newClientSecret, ...) instead of emitting an empty
// bean, which would fail serialization. The one-time plaintext at creation/regeneration is
// surfaced explicitly as a separate String in the response payload.
@JsonIgnoreType
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientSecret {
  String encodedValue;
  String plainText;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static ClientSecret generate(PasswordHasher passwordHasher) {
    byte[] secretBytes = new byte[32];
    SECURE_RANDOM.nextBytes(secretBytes);
    String plainText = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
    String encodedValue = passwordHasher.hash(plainText);
    return new ClientSecret(encodedValue, plainText);
  }

  public static ClientSecret fromEncoded(String encodedValue) {
    return new ClientSecret(encodedValue, null);
  }

  public ClientSecret withEncodedValue(String encodedValue) {
    return new ClientSecret(encodedValue, this.plainText);
  }
}


