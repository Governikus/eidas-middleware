/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.server;

import java.util.Enumeration;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;


public abstract class HttpPaosServlet extends HttpServlet
{

  /**
   * Generated id
   */
  private static final long serialVersionUID = -3825736452650355693L;

  /**
   * Informations about a HttpServletRequest
   *
   * @param request the request to get informations from
   * @return string with formatted informations about this request
   */
  public static String getRequestInformation(HttpServletRequest request)
  {
    StringBuilder requestInformations = new StringBuilder();
    requestInformations.append("\n=== HttpServletRequest ===\n");
    requestInformations.append("  Requested URL: " + request.getRequestURL() + "\n");
    requestInformations.append("  Requested URI: " + request.getRequestURI() + "\n\n");
    requestInformations.append("  Context Path : " + request.getContextPath() + "\n");
    requestInformations.append("  Remote Addr  : " + request.getRemoteAddr() + "\n");
    requestInformations.append("  Remote Host  : " + request.getRemoteHost() + "\n");
    requestInformations.append("  PathInfo     : " + request.getPathInfo() + "\n");
    requestInformations.append("  Server Name  : " + request.getServerName() + "\n");
    requestInformations.append("  Servlet Path : " + request.getServletPath() + "\n");
    requestInformations.append("  Servlet      : " + request.getContextPath() + "\n");
    requestInformations.append("  Server Port  : " + request.getServerPort() + "\n\n");
    requestInformations.append("=======================\n");
    return requestInformations.toString();
  }



  /**
   * Informations about parameters from a HTTPServletRequest
   *
   * @param request to get the parameters from
   * @return string with a list of all parameters
   */
  public static String getRequestParameterInformation(HttpServletRequest request)
  {
    StringBuilder parameters = new StringBuilder("=== ReceivedParameters ===\n");
    Enumeration<String> parameterNames = request.getParameterNames();
    while (parameterNames.hasMoreElements())
    {
      String nextElement = parameterNames.nextElement();
      parameters.append(" o PARAMETER '" + nextElement.replaceAll("[\n\r\t]", "_") + "'\n");
      parameters.append("   VALUE     '" + request.getParameter(nextElement).replaceAll("[\n\r\t]", "_") + "'\n");
    }
    return parameters.append("\n").toString();
  }

}
