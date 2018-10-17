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

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.entity.ContentType;
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
  {
    handleSAMLRequest(request, response, false);
  }

  /**
   * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    handleSAMLRequest(request, response, true);
  }

  /**
   * Handles the SAML request.
   *
   * @param request request
   * @param response response
   * @param isPost <code>true</code> for HTTP POST, <code>false</code> for HTTP GET
   */
  private void handleSAMLRequest(HttpServletRequest request, HttpServletResponse response, boolean isPost)
  {
    EidasRequest eidasReq = null;
    try
    {
      String relayState = request.getParameter(HttpRedirectUtils.RELAYSTATE_PARAMNAME);
      String samlRequestBase64 = request.getParameter(HttpRedirectUtils.REQUEST_PARAMNAME);

      if (relayState == null || samlRequestBase64 == null)
      {
        throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                     "Query Parameter 'RelayState' or 'SAMLRequest' is missing");
      }

      byte[] samlRequest = getSAMLRequestBytes(isPost, samlRequestBase64);

      log.trace("Incoming SAML request: {}", new String(samlRequest, StandardCharsets.UTF_8));

      // Validate and parse the SAML request
      eidasReq = parseSAMLRequest(samlRequest);

      String sessionID = eidasReq.getId();
      store.insert(new RequestSession(relayState, eidasReq));

      // Check that the consumer URL is equal with the connector's metadata
      if (!Utils.isNullOrEmpty(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL())
          && !ServiceProviderConfig.getFirstProvider()
                                   .getAssertionConsumerURL()
                                   .equals(eidasReq.getAuthnRequest().getAssertionConsumerServiceURL()))
      {
        throw new ErrorCodeException(ErrorCode.WRONG_DESTINATION,
                                     "Given AssertionConsumerServiceURL ist not valid!");
      }

      // Prepare the TcToken URL
      String link = ConfigHolder.getServerURLWithContextPath() + TcToken.TC_TOKEN + "?sessionID=" + sessionID;

      // show the HTML page with the link to start the AusweisApp2
      showHTMLPage(response, link);
    }
    catch (InitializationException | ComponentInitializationException e)
    {
      produceHTMLErrorResponse(response, eidasReq, "Cannot initialize OPENSAML", e);
    }
    catch (SAXException e)
    {
      produceHTMLErrorResponse(response, eidasReq, "The saml message is not valid", e);
    }
    catch (DataFormatException e)
    {
      produceHTMLErrorResponse(response,
                               eidasReq,
                               "DataFormatException while inflating samlRequestBase64",
                               e);
    }
    catch (XMLParserException | UnmarshallingException e)
    {
      produceHTMLErrorResponse(response, eidasReq, "Error parsing saml xml", e);
    }
    catch (ErrorCodeException e)
    {
      produceHTMLErrorResponse(response, eidasReq, e.getMessage(), e);
    }
    catch (IOException e)
    {
      produceHTMLErrorResponse(response, eidasReq, "Received IOException", e);
    }
    catch (SQLException e)
    {
      produceHTMLErrorResponse(response, eidasReq, "Can not store request", e);
    }
    catch (Exception e)
    {
      produceHTMLErrorResponse(response, eidasReq, "Cannot parse SAML Request", e);
    }
  }

  /**
   * Return the HTML page to start the AusweisApp2
   *
   * @param response The {@link HttpServletResponse} to return the response
   * @param link The TcToken URL
   */
  private void showHTMLPage(HttpServletResponse response, String link) throws IOException
  {
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

  /**
   * Validate and parse the SAML request
   *
   * @return the parsed {@link EidasRequest}
   */
  private EidasRequest parseSAMLRequest(byte[] samlRequest)
    throws IOException, SAXException, ErrorCodeException, UnmarshallingException, InitializationException,
    XMLParserException, ComponentInitializationException
  {
    try (InputStream is = new ByteArrayInputStream(samlRequest))
    {
      EidasSaml.validateXMLRequest(is, true);
      List<X509Certificate> authors = new ArrayList<>();
      authors.add(ServiceProviderConfig.getFirstProvider().getSignatureCert());
      return EidasSaml.parseRequest(is, authors);
    }
  }

  /**
   * Return the SAML request byte array from the base64 encoded string
   */
  private byte[] getSAMLRequestBytes(boolean isPost, String samlRequestBase64)
    throws DataFormatException, ErrorCodeException
  {
    byte[] samlRequest;

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
      log.warn("cannot parse base64 encoded SAML request: {}", samlRequestBase64);
      throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                   "cannot parse base64 encoded SAML request");
    }

    log.trace("Incoming SAML request: {}", new String(samlRequest, StandardCharsets.UTF_8));
    return samlRequest;
  }

  /**
   * Shows the HTML error response
   *
   * @param response The {@link HttpServletResponse} to return the response
   * @param eidasReq The {@link EidasRequest} of the request or null
   * @param errorMessage The error message
   * @param exception The original exception
   */
  private static void produceHTMLErrorResponse(HttpServletResponse response,
                                               EidasRequest eidasReq,
                                               String errorMessage,
                                               Exception exception)
  {
    if (eidasReq != null)
    {
      log.warn("Error in request from provider with ConsumerServiceURL " + eidasReq.getDestination());
      log.warn("Request id " + eidasReq.getId());
    }
    log.warn("Exception during processing of SAML request", exception);
    response.setStatus(400);
    try
    {
      response.setContentType(ContentType.TEXT_HTML.getMimeType());
      if (StringUtil.notNullOrEmpty(errorMessage))
      {
        response.getWriter().write(Utils.createErrorMessage(errorMessage));
      }
      else
      {
        response.getWriter()
                .write(Utils.createErrorMessage("Caught exception during SAML request processing"));
      }
    }
    catch (IOException e)
    {
      log.warn(e.getLocalizedMessage(), e);
    }
  }
}
