/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Servlet implementation class RequestReceiver
 */
@Slf4j
@WebServlet(RequestReceiver.REQUEST_RECEIVER)
public class RequestReceiver extends HttpServlet
{

  private static final long serialVersionUID = 1L;

  public static final String REQUEST_RECEIVER = "/RequestReceiver";

  private final SessionStore store;

  /**
   * @see HttpServlet#HttpServlet()
   */
  public RequestReceiver(SessionStore store)
  {
    this.store = store;
  }

  /**
   * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
  {
    parseSAMLRequest(request, response, false);
  }

  /**
   * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
  {
    parseSAMLRequest(request, response, true);
  }

  /**
   * Parses the SAML request.
   *
   * @param request request
   * @param response response
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   */
  protected void parseSAMLRequest(HttpServletRequest request, HttpServletResponse response, boolean isPost)
  {
    EidasRequest eidasReq = null;
    String lastErrorMessage = null;
    Exception lastException = null;

    byte[] samlRequest = null;
    String relayState = request.getParameter(HttpRedirectUtils.RELAYSTATE_PARAMNAME);
    String samlRequestBase64 = request.getParameter(HttpRedirectUtils.REQUEST_PARAMNAME);
    try
    {
      if (isPost)
      {
        samlRequest = DatatypeConverter.parseBase64Binary(samlRequestBase64);
      }
      else
      {
        samlRequest = HttpRedirectUtils.inflate(samlRequestBase64);
      }

      if (samlRequest == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                     ErrorCode.ILLEGAL_REQUEST_SYNTAX + " cannot resolve encoding of "
                                                                       + samlRequestBase64);
      }

      try (InputStream is = new ByteArrayInputStream(samlRequest))
      {
        EidasSaml.validateXMLRequest(is, true);
        List<X509Certificate> authors = new ArrayList<>();
        authors.add(ServiceProviderConfig.getFirstProvider().getSignatureCert());
        eidasReq = EidasSaml.parseRequest(is, authors);
      }
      String sessionID = eidasReq.getId();
      store.insert(new RequestSession(relayState, eidasReq));

      if (!Utils.isNullOrEmpty(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL())
          && !ServiceProviderConfig.getFirstProvider()
                                   .getAssertionConsumerURL()
                                   .equals(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL()))
      {
        throw new ErrorCodeException(ErrorCode.WRONG_DESTINATION,
                                     "Given AssertionConsumerServiceURL ist not valid!");
      }

      String link = ConfigHolder.getServerURLWithContextPath() + TcToken.TC_TOKEN + "?sessionID=" + sessionID;

      // according to spec, there must be a web page with an activation link for the
      // ausweisapp
      // and not a redirect
      InputStream html = RequestReceiver.class.getResourceAsStream("AA2.html");
      BufferedReader reader = new BufferedReader(new InputStreamReader(html, StandardCharsets.UTF_8));
      Writer writer = response.getWriter();
      response.setContentType("text/html");
      for ( String line = reader.readLine() ; line != null ; line = reader.readLine() )
      {
        writer.write(line.replaceAll("TCTOKENURL", URLEncoder.encode(link, StandardCharsets.UTF_8.name())));
      }
      writer.close();
    }
    catch (InitializationException | ComponentInitializationException e)
    {
      lastErrorMessage = "Cannot init OPENSAML";
      lastException = e;
    }
    catch (SAXException e)
    {
      lastErrorMessage = "The saml message is not valid";
      lastException = e;
    }
    catch (DataFormatException e)
    {
      lastErrorMessage = "DataFormatException while inflating  samlRequestBase64";
      lastException = e;
    }
    catch (XMLParserException | UnmarshallingException e1)
    {
      lastErrorMessage = "Error parsing saml xml";
      lastException = e1;
    }
    catch (ErrorCodeException | IOException e1)
    {
      lastErrorMessage = e1.getMessage();
      lastException = e1;
    }
    catch (SQLException e)
    {
      lastErrorMessage = "can not store request";
      lastException = e;
    }
    produceErrorResponse(response, eidasReq, lastErrorMessage, lastException);
  }

  /**
   * Writes the error response in case there is an error message.
   *
   * @param response
   * @param eidasReq
   * @param lastErrorMessage
   * @param lastException
   */
  private static void produceErrorResponse(HttpServletResponse response,
                                           EidasRequest eidasReq,
                                           String lastErrorMessage,
                                           Exception lastException)
  {
    if (StringUtil.notNullOrEmpty(lastErrorMessage))
    {
      if (eidasReq != null)
      {
        log.warn("Error in request from provider with ConsumerServiceURL " + eidasReq.getDestination());
        log.warn("Request id " + eidasReq.getId());
      }
      log.warn("lastException: " + lastException);
      response.setStatus(400);
      try
      {
        response.getWriter().write(Utils.createErrorMessage(lastErrorMessage));
      }
      catch (IOException e1)
      {
        log.warn(e1.getLocalizedMessage(), e1);
      }
    }
  }
}
