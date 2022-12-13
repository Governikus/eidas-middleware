/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.service.PasswordHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;




/**
 * This provider manages the authentication process. The hashed password is read from the password.properties file.
 *
 * @author bpr
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class PasswordFileAuthenticationProvider implements AuthenticationProvider
{

  public static final String USER = "user";

  private final PasswordHandler passwordHandler;

  @Override
  public Authentication authenticate(Authentication authentication)
  {

    // Get the values from the login form
    String loginPassword = authentication.getCredentials().toString();

    // Check if the values from the login form match with the values from the
    // password.properties
    if (BCrypt.checkpw(loginPassword, passwordHandler.getHashedPassword()))
    {
      log.debug("Logged in");
      List<GrantedAuthority> authorities = new ArrayList<>();

      if (passwordHandler.isApplicationPropertiesPasswordSet())
      {
        authorities.add(new SimpleGrantedAuthority("hasPasswordInApplicationProperties"));
      }
      if (passwordHandler.isApplicationPropertiesUserSet())
      {
        authorities.add(new SimpleGrantedAuthority("hasUserInApplicationProperties"));
      }
      // Add default user authority
      authorities.add(new SimpleGrantedAuthority(USER));
      return new UsernamePasswordAuthenticationToken(USER, loginPassword, authorities);
    }
    log.debug("Failed to login");
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication)
  {
    return authentication.equals(UsernamePasswordAuthenticationToken.class);
  }

}
