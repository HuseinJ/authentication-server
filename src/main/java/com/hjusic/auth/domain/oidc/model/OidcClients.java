package com.hjusic.auth.domain.oidc.model;

import com.hjusic.auth.domain.oidc.model.events.OidcClientEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;

import java.util.List;
import java.util.Optional;

public interface OidcClients {

  List<OidcClient> findAll();

  Optional<OidcClient> findById(OAuthClientId id);

  Optional<OidcClient> findByClientId(ClientId clientId);

  OidcClient trigger(OidcClientEvent event);
}

