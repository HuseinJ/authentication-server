package com.hjusic.auth.crypto.model;

/**
 * Domain port for one-way password/secret hashing and verification.
 *
 * <p>The domain and application layers depend on this abstraction instead of a concrete framework
 * type (e.g. Spring Security's {@code PasswordEncoder}), keeping credential hashing a domain
 * concern with the actual algorithm supplied by an infrastructure adapter.
 */
public interface PasswordHasher {

  /** Hashes a plaintext secret, returning the encoded representation to persist. */
  String hash(String plaintext);

  /** Verifies a plaintext secret against a previously hashed value. */
  boolean matches(String plaintext, String hashedValue);
}
