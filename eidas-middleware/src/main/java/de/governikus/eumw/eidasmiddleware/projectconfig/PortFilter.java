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
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
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

  @Value("${server.maxRequestSize:100}")
  private int maxRequestSize;

  // Endpoints for which request body size limits are enforced.
  private static final Set<String> PROTECTED_ENDPOINTS = Set.of(ContextPaths.EIDAS_CONTEXT_PATH
                                                                + ContextPaths.REQUEST_RECEIVER,
                                                                ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.PAOS_SERVLET);


  // Default constructor for spring
  public PortFilter()
  {}

  // Constructor for testing purpose
  PortFilter(int eidasInterfacePort, int adminInterfacePort, int maxRequestSize)
  {
    this.adminInterfacePort = adminInterfacePort;
    this.eidasInterfacePort = eidasInterfacePort;
    this.maxRequestSize = maxRequestSize;
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
      if (!HttpMethod.POST.name().equals(httpServletRequest.getMethod()))
      {
        filterChain.doFilter(httpServletRequest, httpServletResponse);
        return;
      }

      String uri = httpServletRequest.getRequestURI();

      if (PROTECTED_ENDPOINTS.stream().noneMatch(uri::startsWith))
      {
        filterChain.doFilter(httpServletRequest, httpServletResponse);
        return;
      }

      long contentLength = httpServletRequest.getContentLengthLong();

      // -1 means: no Content-Length (e.g. chunked transfer encoding)
      if (contentLength < 0)
      {
        httpServletResponse.sendError(HttpServletResponse.SC_LENGTH_REQUIRED, "Content-Length header required");
        return;
      }

      if (contentLength > (maxRequestSize * 1024L)) // in kb
      {
        httpServletResponse.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                                      "POST body exceeds allowed size");
        return;
      }

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
