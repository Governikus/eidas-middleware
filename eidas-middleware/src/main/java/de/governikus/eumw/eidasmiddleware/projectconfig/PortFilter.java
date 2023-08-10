/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.projectconfig;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import de.governikus.eumw.eidascommon.ContextPaths;
import lombok.extern.slf4j.Slf4j;


/**
 * Filter requests based on port and servlet path to separate between the eidas interface and the admin interface
 */
@Slf4j
@Component
public class PortFilter extends OncePerRequestFilter
{

  @Value("#{${server.adminInterfacePort:}?:0}")
  private int adminInterfacePort;

  @Value("${server.port}")
  private int eidasInterfacePort;

  // Default constructor for spring
  public PortFilter()
  {}

  // Constructor for testing purpose
  PortFilter(int eidasInterfacePort, int adminInterfacePort)
  {
    this.adminInterfacePort = adminInterfacePort;
    this.eidasInterfacePort = eidasInterfacePort;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                  HttpServletResponse httpServletResponse,
                                  FilterChain filterChain)
    throws ServletException, IOException
  {
    // check if the second port is open
    adminInterfacePort = adminInterfacePort == 0 ? eidasInterfacePort : adminInterfacePort;

    // path and port for admin interface
    if (httpServletRequest.getLocalPort() == adminInterfacePort
        && httpServletRequest.getServletPath().startsWith(ContextPaths.ADMIN_CONTEXT_PATH))
    {
      filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
    // path and port for eidas interface
    else if (httpServletRequest.getLocalPort() == eidasInterfacePort
             && httpServletRequest.getServletPath().startsWith(ContextPaths.EIDAS_CONTEXT_PATH))
    {
      filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
    else
    {
      log.warn("Path {} cannot be accessed on port {}",
               httpServletRequest.getServletPath(),
               httpServletRequest.getLocalPort());
      httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
  }
}
