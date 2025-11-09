package com.hjusic.auth.domain.user.model.listener;

import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessStartedEvent;
import com.hjusic.auth.notification.application.NotifyEmail;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class ResetPasswordProcessListener {

  private final NotifyEmail notifyEmail;

  @Value( "${auth.ui}")
  private String UI_URL;

  @EventListener
  private void initiateResetPasswordProcessNotification(ResetPasswordProcessStartedEvent event) {
    notifyEmail.sendNotifiaction(event.getEmail().getValue(), "Reset passwort process started use the following token: " + UI_URL + "/reset?token=" + event.getResetPasswordToken().getValue() + "&username=" + event.getUsername().getValue());
    log.info("Reset password process notification sent to email: {}", event.getEmail());
  }

}
