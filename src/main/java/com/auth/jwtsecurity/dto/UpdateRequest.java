package com.auth.jwtsecurity.dto;


import com.auth.jwtsecurity.model.Role;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UpdateRequest {
  private String fullName = null;
  private String username = null;
  private String password = null;
  private Role role = null;
  private String phoneNumber = null;
  private String email = null;
}
