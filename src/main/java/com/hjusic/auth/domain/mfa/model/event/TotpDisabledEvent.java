package com.hjusic.auth.domain.mfa.model.event;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TotpDisabledEvent extends TotpEvent {

  /** {@code true} when an administrator removed the factor, {@code false} for the user. */
  private boolean resetByAdmin;

  private TotpDisabledEvent(String username, boolean resetByAdmin) {
    super(username);
    this.resetByAdmin = resetByAdmin;
  }

  public static TotpDisabledEvent byUser(String username) {
    return new TotpDisabledEvent(username, false);
  }

  public static TotpDisabledEvent byAdmin(String username) {
    return new TotpDisabledEvent(username, true);
  }

  @Override
  public String getEventType() {
    return "TotpDisabledEvent";
  }
}
