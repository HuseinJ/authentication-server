package com.hjusic.auth.domain.oidc.api;

import com.hjusic.auth.domain.oidc.application.CreateOidcClient;
import com.hjusic.auth.domain.oidc.application.DeleteOidcClient;
import com.hjusic.auth.domain.oidc.application.RegenerateOidcClientSecret;
import com.hjusic.auth.domain.oidc.application.UpdateOidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/oidc/clients")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class OidcClientController {

  private final OidcClients oidcClients;
  private final CreateOidcClient createOidcClient;
  private final UpdateOidcClient updateOidcClient;
  private final DeleteOidcClient deleteOidcClient;
  private final RegenerateOidcClientSecret regenerateOidcClientSecret;

  @GetMapping
  public ResponseEntity<?> getAllClients() {
    return ResponseEntity.ok(oidcClients.findAll());
  }

  @GetMapping("/{id}")
  public ResponseEntity<?> getClient(@PathVariable String id) {
    var validatedId = OAuthClientId.of(id);
    if (validatedId.isLeft()) {
      return ResponseEntity.badRequest().body(Map.of("error", validatedId.getLeft().getMessage()));
    }

    var client = oidcClients.findById(validatedId.get());
    if (client.isEmpty()) {
      return ResponseEntity.notFound().build();
    }

    return ResponseEntity.ok(client.get());
  }

  @PostMapping
  public ResponseEntity<?> createClient(@RequestBody CreateOidcClientRequest request) {
    return createOidcClient.create(
        request.getClientId(),
        request.getClientName(),
        request.getGrantTypes(),
        request.getAuthenticationMethods(),
        request.getRedirectUris(),
        request.getPostLogoutRedirectUris(),
        request.getScopes(),
        request.getTokenSettings(),
        request.getClientSettings()
    ).fold(
        error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
        result -> ResponseEntity.ok(Map.of(
            "client", result,
            "clientSecret", result.getClientSecret().getPlainText(),
            "message", "Store the client secret securely. It will not be shown again."
        ))
    );
  }

  @PutMapping("/{id}")
  public ResponseEntity<?> updateClient(
      @PathVariable String id,
      @RequestBody UpdateOidcClientRequest request) {

    return updateOidcClient.update(
        id,
        request.getClientName(),
        request.getGrantTypes(),
        request.getRedirectUris(),
        request.getPostLogoutRedirectUris(),
        request.getScopes(),
        request.getTokenSettings(),
        request.getClientSettings()
    ).fold(
        error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
        ResponseEntity::ok
    );
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<?> deleteClient(@PathVariable String id) {
    return deleteOidcClient.delete(id)
        .fold(
            error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
            client -> ResponseEntity.ok(Map.of("message", "Client deleted successfully"))
        );
  }

  @PostMapping("/{id}/regenerate-secret")
  public ResponseEntity<?> regenerateClientSecret(@PathVariable String id) {
    return regenerateOidcClientSecret.regenerate(id)
        .fold(
            error -> ResponseEntity.badRequest().body(Map.of("error", error.getMessage())),
            result -> ResponseEntity.ok(Map.of(
                "client", result.client(),
                "clientSecret", result.plainTextSecret(),
                "message", "Store the new client secret securely. It will not be shown again."
            ))
        );
  }
}