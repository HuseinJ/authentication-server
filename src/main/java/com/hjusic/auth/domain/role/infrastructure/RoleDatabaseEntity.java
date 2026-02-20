package com.hjusic.auth.domain.role.infrastructure;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleDatabaseEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  @Enumerated(EnumType.STRING)
  private RoleName name;

  @Column(length = 500)
  private String description;

  @JsonIgnore
  @ManyToMany(mappedBy = "roles")
  @Builder.Default
  private Set<UserDatabaseEntity> users = new HashSet<>();

  public RoleDatabaseEntity(RoleName name, String description) {
    this.name = name;
    this.description = description;
  }
}
