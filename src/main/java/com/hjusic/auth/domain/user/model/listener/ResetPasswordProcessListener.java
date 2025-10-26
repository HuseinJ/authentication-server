package com.hjusic.auth.domain.user.model.listener;

import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessStartedEvent;
import com.hjusic.auth.notification.application.NotifyEmail;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class ResetPasswordProcessListener {

  private final NotifyEmail notifyEmail;

  @EventListener
  private void initiateResetPasswordProcessNotification(ResetPasswordProcessStartedEvent event) {
    notifyEmail.sendNotifiaction(event.getEmail().getValue(), "Reset passwort process started use the following token: " + event.getResetPasswordToken().getValue());
    log.info("Reset password process notification sent to email: {}", event.getEmail());
  }

}
