/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.projectconfig.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import lombok.extern.slf4j.Slf4j;


/**
 * author Pascal Knueppel <br>
 * created at: 04.04.2018 - 09:42 <br>
 * <br>
 * this filter is intended to solve the encoding problem with the webpages that cause Umlauts to be destroyed
 * after a post requests
 */
@Slf4j
public class Utf8Filter implements Filter
{

  /**
   * {@inheritDoc}
   */
  @Override
  public void init(FilterConfig filterConfig) throws ServletException
  {
    // do nothing
  }

  /**
   * sets the encoding of any request and any response to UTF-8
   */
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException
  {
    request.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    chain.doFilter(request, response);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void destroy()
  {
    // do nothing
  }
}
