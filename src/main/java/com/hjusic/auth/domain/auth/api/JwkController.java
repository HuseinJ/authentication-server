package com.hjusic.auth.domain.auth.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class JwkController {

  @Value("${jwt.public-key}")
  private String publicKeyPem;

  @GetMapping("/jwks.json")
  public Map<String, Object> jwks() throws Exception {
    RSAPublicKey publicKey = loadPublicKey(publicKeyPem);

    // Convert RSA public key to JWK format manually
    String modulus = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(publicKey.getModulus().toByteArray());
    String exponent = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(publicKey.getPublicExponent().toByteArray());

    Map<String, Object> jwk = Map.of(
        "kty", "RSA",
        "use", "sig",
        "alg", "RS256",
        "kid", "default",
        "n", modulus,
        "e", exponent
    );

    return Map.of("keys", List.of(jwk));
  }

  private RSAPublicKey loadPublicKey(String publicKeyPem) throws Exception {
    String publicKeyContent = publicKeyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");

    byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }
}
