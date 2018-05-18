/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas;

import java.util.Arrays;

import javax.annotation.PostConstruct;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

/**
 * This provider manages the authentication process. The username and the hashed
 * password are read from the application.properties file. To create a hashed
 * password, see the password-generator project.
 * 
 * @author bpr
 *
 */
@Component
public class PasswordFileAuthenticationProvider implements AuthenticationProvider {

	private static final Log LOG = LogFactory.getLog(PasswordFileAuthenticationProvider.class);

	@Value("${poseidas.admin.username}")
	private String username;

	@Value("${poseidas.admin.hashed.password}")
	private String hashedPassword;

	@PostConstruct
	public void checkForDefaultPassword() {
		String defaultPassword = "$2a$10$lRmdsCOtjoBLb8bKDrviueoW1aUkIcUmnImu4xZlOzvfc5k9WcKAi";
		if (defaultPassword.equals(hashedPassword)) {
			LOG.fatal("YOU HAVE NOT CHANGED THE DEFAULT PASSWORD!");
		}
	}

	@Override
  public Authentication authenticate(Authentication authentication)
  {
		// Get the values from the login form
		String loginName = authentication.getName();
		String loginPassword = authentication.getCredentials().toString();

		// Check if the values from the login form match with the values from the
		// application.properties
		if (username.equals(loginName) && BCrypt.checkpw(loginPassword, hashedPassword)) {
			LOG.debug(loginName + "logged in");
			return new UsernamePasswordAuthenticationToken(loginName, loginPassword,
					Arrays.asList(new SimpleGrantedAuthority("user")));
		}
		LOG.debug(loginName + "failed to login");
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
