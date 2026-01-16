package com.hjusic.auth.domain.oidc.model;

import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import io.vavr.control.Option;

import java.util.List;

public interface OidcClients {

  OidcClient save(OidcClient client);

  Option<OidcClient> findById(OAuthClientId id);

  Option<OidcClient> findByClientId(String clientId);

  List<OidcClient> findAll();

  void delete(OidcClient client);
}

