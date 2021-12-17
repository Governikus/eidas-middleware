/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.paos.handler;

import java.io.IOException;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Utils;


public class PaosHandlerFactory
{

  private static final Log LOG = LogFactory.getLog(PaosHandlerFactory.class.getName());

  private PaosHandlerFactory()
  {
    super();
  }

  /**
   * Creates a new handler for the given HTTP servlet request.
   *
   * @param request the HTTP servlet request
   * @throws PaosHandlerException if the talked PAOS is wrong
   * @throws IOException on any IO errors
   */
  public static AbstractPaosHandler newInstance(HttpServletRequest request) throws PaosHandlerException, IOException
  {
    byte[] requestBody = readRequestbody(request);
    try
    {
      return tryCreateNewInstances(request, requestBody);
    }
    catch (IllegalArgumentException e)
    {
      LOG.warn("PAOS Conversation stopped: Can not create new instance for request", e);
      throw new PaosHandlerException("PAOS Conversation stopped: Can not create new instance for request ", 400);
    }
  }

  private static AbstractPaosHandler tryCreateNewInstances(HttpServletRequest request, byte[] requestBody)
    throws PaosHandlerException, IOException
  {
    return new DefaultPaosHandler(request, requestBody);
  }

  private static byte[] readRequestbody(HttpServletRequest request) throws IOException
  {
    try (ServletInputStream in = request.getInputStream())
    {
      return Utils.readBytesFromStream(in);
    }
  }
}
