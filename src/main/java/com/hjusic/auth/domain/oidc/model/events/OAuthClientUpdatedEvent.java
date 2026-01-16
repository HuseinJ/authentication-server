package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper=false)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientUpdatedEvent extends OidcClientEvent {

  public static OAuthClientUpdatedEvent of(OAuthClient client) {
      var event = new OAuthClientUpdatedEvent();
      event.setClient(client);
      return event;
  }
}
