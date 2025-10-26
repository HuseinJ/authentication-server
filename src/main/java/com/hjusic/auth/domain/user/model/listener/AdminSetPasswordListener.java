package com.hjusic.auth.domain.user.model.listener;

import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class AdminSetPasswordListener {

  @Value("${auth.admin.username}")
  private String username;

  private final Users users;

  @EventListener
  private void initiatePasswordResetForAdmin(UserCreatedEvent userCreatedEvent) {
    if (!userCreatedEvent.getUsername().getValue().equals(username)) {
      return;
    }

    log.info("Initiating password reset for admin user: {}", username);

    var admin = users.findByUsername(username);
    if (admin.isLeft()) {
      throw new IllegalStateException("Admin user does not exist");
    }

    users.trigger(admin.get().startResetPasswordProcess());

    log.info("Password reset for admin user: {}", username);
  }

}
