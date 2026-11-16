package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.mfa.model.SecondFactorEnrollment;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Collects every {@link SecondFactorEnrollment} bean, so a new MFA method only has to provide one
 * to take part in the login flows.
 */
@Service
@RequiredArgsConstructor
public class SecondFactorRegistry {

  private final List<SecondFactorEnrollment> enrollments;

  public Set<SecondFactorType> enrolledFactors(String username) {
    Set<SecondFactorType> enrolled = EnumSet.noneOf(SecondFactorType.class);
    for (SecondFactorEnrollment enrollment : enrollments) {
      if (enrollment.isEnrolled(username)) {
        enrolled.add(enrollment.type());
      }
    }
    return enrolled;
  }
}
