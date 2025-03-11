/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.authentication.paos;

import java.io.IOException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.paosservlet.paos.handler.AbstractPaosHandler;
import de.governikus.eumw.poseidas.paosservlet.paos.handler.PaosHandlerException;
import de.governikus.eumw.poseidas.paosservlet.paos.handler.PaosHandlerFactory;


/**
 * PaosReceiver handling the PAOS messages on TLS PSK streams
 *
 * @author <a href="mail:obe@bos-bremen.de">Ole Behrens</a>
 */
@WebServlet(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.PAOS_SERVLET)
public class PaosReceiver extends HttpServlet
{

  private static final long serialVersionUID = 3323320851L;

  private static final Log LOG = LogFactory.getLog(PaosReceiver.class.getName());

  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException
  {
    LOG.debug("Get on receiver");
    try
    {
      resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                     "HTTP GET request is not supported by this Servlet, use HTTP POST only");
    }
    catch (Exception e)
    {
      LOG.error(e.getMessage(), e);
      resp.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException
  {
    try
    {
      createPaosResponse(req, resp);
    }
    catch (IOException e)
    {
      LOG.error(e.getMessage(), e);
      resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private void createPaosResponse(HttpServletRequest req, HttpServletResponse resp) throws IOException
  {

    try
    {
      AbstractPaosHandler handler = PaosHandlerFactory.newInstance(req);
      // Handle PAOS message
      handler.writeResponse(resp);
    }
    catch (PaosHandlerException e)
    {
      LOG.warn(e.getMessage(), e);
      resp.sendError(e.getStatus(), e.getMessage());
    }
  }
}
