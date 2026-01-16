package com.hjusic.auth.domain.oidc.model.events;

import com.hjusic.auth.domain.oidc.model.OAuthClient;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper=false)
@NoArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class OAuthClientDeletedEvent extends OidcClientEvent{

  public static OAuthClientDeletedEvent of(OAuthClient client) {
      var event = new OAuthClientDeletedEvent();
      event.setClient(client);
      return event;
  }
}
