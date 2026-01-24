package com.hjusic.auth.domain.oidc.infrastructure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Optional;

@Component
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

  private final OAuth2AuthorizationJpaRepository authorizationRepository;
  private final RegisteredClientRepository registeredClientRepository;
  private final ObjectMapper objectMapper;

  public JpaOAuth2AuthorizationService(OAuth2AuthorizationJpaRepository authorizationRepository,
      RegisteredClientRepository registeredClientRepository, @Qualifier("oauth2ObjectMapper") ObjectMapper objectMapper) {
    this.authorizationRepository = authorizationRepository;
    this.registeredClientRepository = registeredClientRepository;
    this.objectMapper = objectMapper;
  }

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void save(OAuth2Authorization authorization) {
    var entity = toEntity(authorization);
    authorizationRepository.save(entity);
  }

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void remove(OAuth2Authorization authorization) {
    authorizationRepository.deleteById(authorization.getId());
  }

  @Override
  @Transactional(readOnly = true)
  public OAuth2Authorization findById(String id) {
    return authorizationRepository.findById(id)
        .map(this::toAuthorization)
        .orElse(null);
  }

  @Override
  @Transactional(readOnly = true)
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    Optional<OAuth2AuthorizationEntity> result;

    if (tokenType == null) {
      result = authorizationRepository.findByAnyToken(token);
    } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
      result = authorizationRepository.findByState(token);
    } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
      result = authorizationRepository.findByAuthorizationCodeValue(token);
    } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
      result = authorizationRepository.findByAccessTokenValue(token);
    } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
      result = authorizationRepository.findByRefreshTokenValue(token);
    } else {
      result = Optional.empty();
    }

    return result.map(this::toAuthorization).orElse(null);
  }

  private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
    var builder = OAuth2AuthorizationEntity.builder()
        .id(authorization.getId())
        .registeredClientId(authorization.getRegisteredClientId())
        .principalName(authorization.getPrincipalName())
        .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
        .authorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","))
        .attributes(writeMap(authorization.getAttributes()))
        .state(authorization.getAttribute(OAuth2ParameterNames.STATE));

    var authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
    if (authorizationCode != null) {
      builder
          .authorizationCodeValue(authorizationCode.getToken().getTokenValue())
          .authorizationCodeIssuedAt(authorizationCode.getToken().getIssuedAt())
          .authorizationCodeExpiresAt(authorizationCode.getToken().getExpiresAt())
          .authorizationCodeMetadata(writeMap(authorizationCode.getMetadata()));
    }

    var accessToken = authorization.getToken(OAuth2AccessToken.class);
    if (accessToken != null) {
      builder
          .accessTokenValue(accessToken.getToken().getTokenValue())
          .accessTokenIssuedAt(accessToken.getToken().getIssuedAt())
          .accessTokenExpiresAt(accessToken.getToken().getExpiresAt())
          .accessTokenMetadata(writeMap(accessToken.getMetadata()))
          .accessTokenType(accessToken.getToken().getTokenType().getValue())
          .accessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
    }

    var refreshToken = authorization.getToken(OAuth2RefreshToken.class);
    if (refreshToken != null) {
      builder
          .refreshTokenValue(refreshToken.getToken().getTokenValue())
          .refreshTokenIssuedAt(refreshToken.getToken().getIssuedAt())
          .refreshTokenExpiresAt(refreshToken.getToken().getExpiresAt())
          .refreshTokenMetadata(writeMap(refreshToken.getMetadata()));
    }

    var oidcIdToken = authorization.getToken(OidcIdToken.class);
    if (oidcIdToken != null) {
      builder
          .oidcIdTokenValue(oidcIdToken.getToken().getTokenValue())
          .oidcIdTokenIssuedAt(oidcIdToken.getToken().getIssuedAt())
          .oidcIdTokenExpiresAt(oidcIdToken.getToken().getExpiresAt())
          .oidcIdTokenMetadata(writeMap(oidcIdToken.getMetadata()))
          .oidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
    }

    return builder.build();
  }

  private OAuth2Authorization toAuthorization(OAuth2AuthorizationEntity entity) {
    RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
    if (registeredClient == null) {
      throw new IllegalStateException("Registered client not found: " + entity.getRegisteredClientId());
    }

    var builder = OAuth2Authorization.withRegisteredClient(registeredClient)
        .id(entity.getId())
        .principalName(entity.getPrincipalName())
        .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
        .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
        .attributes(attrs -> attrs.putAll(readMap(entity.getAttributes())));

    if (entity.getState() != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
    }

    if (entity.getAuthorizationCodeValue() != null) {
      var authorizationCode = new OAuth2AuthorizationCode(
          entity.getAuthorizationCodeValue(),
          entity.getAuthorizationCodeIssuedAt(),
          entity.getAuthorizationCodeExpiresAt()
      );
      builder.token(authorizationCode, metadata -> metadata.putAll(readMap(entity.getAuthorizationCodeMetadata())));
    }

    if (entity.getAccessTokenValue() != null) {
      var accessToken = new OAuth2AccessToken(
          OAuth2AccessToken.TokenType.BEARER,
          entity.getAccessTokenValue(),
          entity.getAccessTokenIssuedAt(),
          entity.getAccessTokenExpiresAt(),
          StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes())
      );
      builder.token(accessToken, metadata -> metadata.putAll(readMap(entity.getAccessTokenMetadata())));
    }

    if (entity.getRefreshTokenValue() != null) {
      var refreshToken = new OAuth2RefreshToken(
          entity.getRefreshTokenValue(),
          entity.getRefreshTokenIssuedAt(),
          entity.getRefreshTokenExpiresAt()
      );
      builder.token(refreshToken, metadata -> metadata.putAll(readMap(entity.getRefreshTokenMetadata())));
    }

    if (entity.getOidcIdTokenValue() != null) {
      var idToken = new OidcIdToken(
          entity.getOidcIdTokenValue(),
          entity.getOidcIdTokenIssuedAt(),
          entity.getOidcIdTokenExpiresAt(),
          readMap(entity.getOidcIdTokenClaims())
      );
      builder.token(idToken, metadata -> metadata.putAll(readMap(entity.getOidcIdTokenMetadata())));
    }

    return builder.build();
  }

  private String writeMap(Map<String, Object> map) {
    try {
      return objectMapper.writeValueAsString(map);
    } catch (Exception e) {
      throw new IllegalArgumentException("Error writing map", e);
    }
  }

  private Map<String, Object> readMap(String json) {
    try {
      if (!StringUtils.hasText(json)) {
        return Map.of();
      }
      return objectMapper.readValue(json, new TypeReference<>() {});
    } catch (Exception e) {
      throw new IllegalArgumentException("Error reading map", e);
    }
  }
}