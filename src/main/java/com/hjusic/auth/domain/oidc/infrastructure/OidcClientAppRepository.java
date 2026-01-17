package com.hjusic.auth.domain.oidc.infrastructure;

import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientCreatedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientDeletedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientSecretRegeneratedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientUpdatedEvent;
import com.hjusic.auth.domain.oidc.model.events.OidcClientEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import com.hjusic.auth.event.model.DomainEventPublisher;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OidcClientAppRepository implements OidcClients {

  private final OidcClientDatabaseRepository oidcClientDatabaseRepository;
  private final DomainEventPublisher domainEventPublisher;

  @Override
  public List<OidcClient> findAll() {
    return oidcClientDatabaseRepository.findAll().stream().map(OidcClientMapper::toDomain).toList();
  }

  @Override
  public Optional<OidcClient> findById(OAuthClientId id) {
    var client = oidcClientDatabaseRepository.findById(id.getValue().toString());

    return client.map(OidcClientMapper::toDomain);
  }

  @Override
  public Optional<OidcClient> findByClientId(ClientId clientId) {
    var client = oidcClientDatabaseRepository.findByClientId(clientId.getValue());

    return client.map(OidcClientMapper::toDomain);
  }

  @Override
  public OidcClient trigger(OidcClientEvent event) {
    var client = switch (event) {
      case OAuthClientCreatedEvent e -> handle(e);
      case OAuthClientDeletedEvent e -> handle(e);
      case OAuthClientSecretRegeneratedEvent e -> handle(e);
      case OAuthClientUpdatedEvent e -> handle(e);
      default -> throw new IllegalArgumentException("Unhandled event type: " + event.getClass());
    };

    domainEventPublisher.publish(event);

    return client;
  }

  private OidcClient handle(OAuthClientUpdatedEvent e) {
    var existingEntity = oidcClientDatabaseRepository.findById(e.getClient().getId().toString())
        .orElseThrow(() -> new IllegalArgumentException("OIDC Client not found: " + e.getClient().getId()));

    OidcClientMapper.updateEntity(existingEntity, e.getClient());
    var savedEntity = oidcClientDatabaseRepository.save(existingEntity);
    return OidcClientMapper.toDomain(savedEntity);
  }

  private OidcClient handle(OAuthClientSecretRegeneratedEvent e) {
    var existingEntity = oidcClientDatabaseRepository.findById(e.getClient().getId().toString())
        .orElseThrow(() -> new IllegalArgumentException("OIDC Client not found: " + e.getClient().getId()));

    existingEntity.setClientSecret(e.getClient().getClientSecret().getEncodedValue());
    var savedEntity = oidcClientDatabaseRepository.save(existingEntity);
    return OidcClientMapper.toDomain(savedEntity);
  }

  private OidcClient handle(OAuthClientDeletedEvent e) {
    oidcClientDatabaseRepository.deleteById(e.getClient().getId().toString());
    return e.getClient();
  }

  private OidcClient handle(OAuthClientCreatedEvent e) {
    var entity = OidcClientMapper.toEntity(e.getClient());
    var savedEntity = oidcClientDatabaseRepository.save(entity);
    return OidcClientMapper.toDomain(savedEntity);
  }
}
