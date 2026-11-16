package com.hjusic.auth.domain.mfa.model;

/**
 * Tells whether a user has a specific second factor enrolled. One implementation exists per
 * {@link SecondFactorType}; login requires one of the enrolled factors on top of the password.
 */
public interface SecondFactorEnrollment {

  SecondFactorType type();

  boolean isEnrolled(String username);
}
