package com.hjusic.auth.domain.oidc.model;

import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import io.vavr.control.Option;

import java.util.List;

public interface OAuthClients {

  OAuthClient save(OAuthClient client);

  Option<OAuthClient> findById(OAuthClientId id);

  Option<OAuthClient> findByClientId(String clientId);

  List<OAuthClient> findAll();

  void delete(OAuthClient client);
}

