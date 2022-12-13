/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import de.governikus.eumw.eidascommon.ContextPaths;


/**
 * Spring Security configuration for the two application parts eIDAS (SAML) and web admin
 *
 * @author bpr
 */
@EnableWebSecurity
public class POSeIDASSecurityConfig
{

  @Autowired
  PasswordFileAuthenticationProvider authenticationProvider;

  /**
   * This security configuration limits the access to the web admin. Static resources and the login page can be accessed
   * without authentication, everything else must be authenticated.
   */
  @Configuration
  @Order(1)
  public static class WebAdminSecurity extends WebSecurityConfigurerAdapter
  {

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
      http.antMatcher(ContextPaths.ADMIN_CONTEXT_PATH + "/**");
      http.authorizeRequests(authorize -> authorize.mvcMatchers(ContextPaths.ADMIN_CONTEXT_PATH + "/webjars/**",
                                                                ContextPaths.ADMIN_CONTEXT_PATH + "/css/**",
                                                                ContextPaths.ADMIN_CONTEXT_PATH + "/images/**",
                                                                ContextPaths.ADMIN_CONTEXT_PATH + "/js/**",
                                                                ContextPaths.ADMIN_CONTEXT_PATH + "/setNewPassword")
                                                   .permitAll()
                                                   .mvcMatchers(ContextPaths.ADMIN_CONTEXT_PATH + "/**")
                                                   .authenticated());
      http.formLogin()
          .loginPage(ContextPaths.ADMIN_CONTEXT_PATH + "/login")
          .defaultSuccessUrl(ContextPaths.ADMIN_CONTEXT_PATH + "/dashboard")
          .permitAll()
          .and()
          .logout()
          .logoutRequestMatcher(new AntPathRequestMatcher(ContextPaths.ADMIN_CONTEXT_PATH + "/logout",
                                                          HttpMethod.GET.name()))
          .permitAll()
          .and()
          .headers()
          .contentSecurityPolicy("script-src 'self'");
    }
  }

  /**
   * Spring security for the eIDAS (SAML) part. No authentication is necessary.
   */
  @Configuration
  @Order(2)
  public static class EidasSecurity extends WebSecurityConfigurerAdapter
  {

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
      http.antMatcher(ContextPaths.EIDAS_CONTEXT_PATH + "/**");
      http.authorizeRequests(authorize -> authorize.anyRequest().permitAll());
      http.csrf().disable();
    }

  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth)
  {
    auth.authenticationProvider(authenticationProvider);
  }
}
