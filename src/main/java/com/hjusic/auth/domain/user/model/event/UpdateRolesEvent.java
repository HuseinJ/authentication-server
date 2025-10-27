package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.util.Set;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class UpdateRolesEvent extends UserEvent {

  private Set<Role> roles;

  public static UpdateRolesEvent of(Username username, Set<Role> roles) {
    UpdateRolesEvent event = new UpdateRolesEvent();
    event.setEventId(java.util.UUID.randomUUID().toString());
    event.setOccurredOn(java.time.Instant.now());
    event.setUsername(username);
    event.setRoles(roles);
    return event;
  }

  @Override
  public String getEventType() {
    return "UpdateRolesEvent";
  }
}
