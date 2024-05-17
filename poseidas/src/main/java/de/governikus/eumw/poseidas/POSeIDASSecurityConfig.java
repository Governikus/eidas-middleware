/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import de.governikus.eumw.eidascommon.ContextPaths;


/**
 * Spring Security configuration for the two application parts eIDAS (SAML) and web admin
 *
 * @author bpr
 */
@EnableWebSecurity
@Configuration
public class POSeIDASSecurityConfig
{

  /**
   * This security configuration limits the access to the web admin. Static resources and the login page can be accessed
   * without authentication, everything else must be authenticated.
   */
  @Bean
  public SecurityFilterChain adminUiSecurityFilterChain(HttpSecurity httpSecurity,
                                                        PasswordFileAuthenticationProvider authenticationProvider,
                                                        HandlerMappingIntrospector introspector)
    throws Exception
  {


    httpSecurity.securityMatcher(ContextPaths.ADMIN_CONTEXT_PATH + "/**");
    httpSecurity.authorizeHttpRequests(matcherRegistry -> matcherRegistry.requestMatchers(new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/webjars/**"),
                                                                                          new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/css/**"),
                                                                                          new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/images/**"),
                                                                                          new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/js/**"),
                                                                                          new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/setNewPassword"))
                                                                         .permitAll()
                                                                         .requestMatchers(new MvcRequestMatcher(introspector,
                                                                                                                ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                                              + "/**"))
                                                                         .authenticated());

    httpSecurity.formLogin(configurer -> configurer.loginPage(ContextPaths.ADMIN_CONTEXT_PATH + "/login")
                                                   .defaultSuccessUrl(ContextPaths.ADMIN_CONTEXT_PATH
                                                                      + ContextPaths.DASHBOARD)
                                                   .permitAll());
    httpSecurity.logout(configurer -> configurer.logoutRequestMatcher(new AntPathRequestMatcher(ContextPaths.ADMIN_CONTEXT_PATH
                                                                                                + "/logout",
                                                                                                HttpMethod.GET.name()))
                                                .permitAll());
    httpSecurity.headers(configurer -> configurer.contentSecurityPolicy(contentSecurityPolicyConfig -> contentSecurityPolicyConfig.policyDirectives("script-src 'self'")));
    httpSecurity.authenticationProvider(authenticationProvider);

    return httpSecurity.build();
  }

  /**
   * Spring security for the eIDAS (SAML) part. No authentication is necessary.
   */
  @Bean
  public SecurityFilterChain eidasSecurityFilterChain(HttpSecurity httpSecurity) throws Exception
  {
    httpSecurity.securityMatcher(ContextPaths.EIDAS_CONTEXT_PATH + "/**");
    httpSecurity.authorizeHttpRequests(matcherRegistry -> matcherRegistry.anyRequest().permitAll());
    httpSecurity.csrf(configurer -> configurer.disable());

    return httpSecurity.build();
  }

}
