/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.springboot;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


/**
 * While testing with the HTMLUnit-Framework, sometimes the URL parameter JSESSIONID is appended to the RequestURL,
 * which leads to errors. This filter removes the JSESSIONID parameter.
 */
@Component
public class SessionFilter extends OncePerRequestFilter
{

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException
  {
    logger.debug("In SessionFilter");
    if (request.getRequestURI().contains("jsessionid"))
    {
      String newURI = request.getRequestURI().substring(0, request.getRequestURI().indexOf(";"));
      logger.debug("New RequestURL: " + newURI);

      request.getRequestDispatcher(newURI).forward(request, response);
      return;
    }
    filterChain.doFilter(request, response);
  }
}
