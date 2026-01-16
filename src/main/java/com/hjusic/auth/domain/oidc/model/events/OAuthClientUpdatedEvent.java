package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OidcClient;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper=false)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientUpdatedEvent extends OidcClientEvent {

  public static OAuthClientUpdatedEvent of(OidcClient client) {
      var event = new OAuthClientUpdatedEvent();
      event.setClient(client);
      return event;
  }
}
