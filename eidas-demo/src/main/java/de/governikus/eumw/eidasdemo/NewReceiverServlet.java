/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Document;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * This is how to receive a eIDAS SAML response in HTTP Redirect binding.<br>
 * The eIDAS Middleware redirects the users browser to this servlet. The request contains the SAML response
 * and we parse it but there is no sessionID in this request. The result of the eIDAS response is stored with
 * a new sessionID in the {@link NewReceiverServlet#errorsMap} or {@link NewReceiverServlet#resultsXMLMap}.
 * Then this servlet redirects the user's browser to the same URL but this time with the sessionID. This time
 * the servlet retrieves the data to the corresponding sessionID and displays the result page.<br>
 * The URL this Sevlet is deployed under must match the same origin of the subject URL in the CVC description
 * (Beschreibung des Berechtigungszertifikats).
 * 
 * @author hme
 * @author prange
 */
@Slf4j
@WebServlet("/NewReceiverServlet")
public class NewReceiverServlet extends HttpServlet
{

  private static final String UNPARSED = "unparsed";

  /**
   * Provides utility methods
   */
  private final SamlExampleHelper helper;

  /**
   * Class to store the errors of a SAML response.
   */
  @Data
  private static class ErrorDetails
  {

    private String[] errors;
  }

  private static final long serialVersionUID = 1L;

  /**
   * Stores the sessionID and the ErrorDetails
   */
  private static Map<String, ErrorDetails> errorsMap = new HashMap<>();

  /**
   * Stores the sessionID and the raw XML eIDASResponse as well as the extracted data from the response if
   * possible.
   */
  private static Map<String, String> resultsXMLMap = new HashMap<>();


  /**
   * Default constructor for spring autowiring
   */
  @Autowired
  public NewReceiverServlet(SamlExampleHelper helper)
  {
    this.helper = helper;
  }


  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    processRequest(request, response, false);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
  {
    processRequest(req, resp, true);
  }

  /**
   * Process the incoming request dependent if the sessionID is present
   */
  private void processRequest(HttpServletRequest request, HttpServletResponse response, boolean isPost)
  {
    try
    {
      String sessionID = request.getParameter("sessionID");
      if (sessionID == null)
      {
        processIncomingSAMLResponse(request, response, isPost);
      }
      else
      {
        displayResultPage(response, sessionID);
      }
    }
    catch (IOException e)
    {
      log.error(e.getMessage(), e);
      helper.handleResponseException(response);
    }
  }

  /**
   * This method is called when the eIDAS Middleware sent the user's browser to this servlet. The eIDAs
   * response data is extracted and the browser is redirected to this servlet with the sessionID.
   */
  private void processIncomingSAMLResponse(HttpServletRequest request,
                                           HttpServletResponse response,
                                           boolean isPost)
    throws IOException
  {
    String sessionID = Utils.generateUniqueID();
    try
    {
      String samlResponseBase64 = request.getParameter(HttpRedirectUtils.RESPONSE_PARAMNAME);

      byte[] samlResponse;
      if (!isPost)
      {
        // check the signature of the SAML response. There is no XML signature in this response but the
        // parameter are signed.
        if (!HttpRedirectUtils.checkQueryString(request.getQueryString(), helper.serverSigCert))
        {
          storeError(sessionID, request, response, "Signaturpr&uuml;fung der SAML-Response fehlgeschlagen!");
          return;
        }

        // inflate and base64 decode the SAML response to get the xml.
        samlResponse = HttpRedirectUtils.inflate(samlResponseBase64);
      }
      else
      {
        samlResponse = DatatypeConverter.parseBase64Binary(samlResponseBase64);
      }

      extractDataFromResponse(sessionID, samlResponse);

      // forward the browser to the result page. at this position a HTTP 302 is needed you are not allowed
      // to do a HTTP 200 and show the errorsMap you want to show. The URL this forward shows to will be
      // opened by the web browser.
      forwardToURL(request, response, sessionID);
    }
    catch (Exception e)
    {
      log.error("got error code from SAML Server", e);
      storeError(sessionID, request, response, e.getMessage(), "");
    }
  }

  /**
   * Parse the eIDAS response and store the data with the sessionID
   *
   * @param sessionID The ID for this response
   * @param samlResponse The response content
   */
  private void extractDataFromResponse(String sessionID, byte[] samlResponse) throws XMLParserException,
    IOException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    String saml = getXMLFromBytes(samlResponse);
    resultsXMLMap.put(sessionID + UNPARSED, String.valueOf(saml));

    try (InputStream is = new ByteArrayInputStream(samlResponse))
    {
      EidasResponse resp = EidasResponse.parse(is,
                                               new X509KeyPair[]{helper.demoDecryptionKeyPair},
                                               new X509Certificate[]{helper.serverSigCert});
      StringBuilder sb = new StringBuilder();

      resp.getAttributes().forEach(e -> {
        sb.append(e.toString());
        sb.append("\n");
      });

      resultsXMLMap.put(sessionID, sb.toString());
    }
  }

  /**
   * Load the data or errors with the sessionID and display this in the user's browser.
   * 
   * @param response response object
   * @param sessionID the sessionID
   */
  private void displayResultPage(HttpServletResponse response, String sessionID) throws IOException
  {
    response.setContentType("text/plain");
    response.setCharacterEncoding("UTF-8");
    if (resultsXMLMap.containsKey(sessionID + UNPARSED))
    {
      response.getWriter().write("" + resultsXMLMap.get(sessionID + UNPARSED));
      resultsXMLMap.remove(sessionID + UNPARSED);
    }
    response.getWriter().write("\n\r");
    response.getWriter().write("\n\r");
    if (resultsXMLMap.containsKey(sessionID))
    {
      response.getWriter().write("" + resultsXMLMap.get(sessionID));
      resultsXMLMap.remove(sessionID);
    }
    if (errorsMap.containsKey(sessionID))
    {
      response.getWriter().write("Error ");
      for ( String s : errorsMap.get(sessionID).getErrors() )
      {
        response.getWriter().write("\n\r");
        response.getWriter().write(s);
      }
    }
  }

  /**
   * This stores an error in our session and forwards the Browser to the result page.
   */
  private void storeError(String sessionID,
                          HttpServletRequest request,
                          HttpServletResponse response,
                          String... details)
    throws IOException
  {
    ErrorDetails result = new ErrorDetails();
    result.setErrors(details);
    errorsMap.put(sessionID, result);

    forwardToURL(request, response, sessionID);
  }

  /**
   * Redirects the browser to the result page.
   */
  private void forwardToURL(HttpServletRequest request, HttpServletResponse response, String sessionID)
    throws IOException
  {
    response.setHeader("Cache-Control", "no-cache, no-store");
    response.setHeader("Pragma", "no-cache");
    response.sendRedirect(response.encodeRedirectURL(Utils.createOwnUrlPrefix(request)
                                                     + request.getContextPath() + "/NewReceiverServlet"
                                                     + "?sessionID=" + sessionID));
  }

  /**
   * Convert the byte array to String containing the xml data
   * 
   * @param value the byte array containing the xml data
   * @return the xml data as a String
   */
  private static String getXMLFromBytes(byte[] value)
  {
    try
    {
      Document doc = XMLObjectProviderRegistrySupport.getParserPool().parse(new ByteArrayInputStream(value));
      Transformer trans = TransformerFactory.newInstance().newTransformer();
      trans.setOutputProperty(OutputKeys.INDENT, "yes");
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      trans.transform(new DOMSource(doc), new StreamResult(bout));

      return new String(bout.toByteArray(), Utils.ENCODING);
    }
    catch (Exception e)
    {
      log.error("Cannot convert the byte array to String", e);
      return "";
    }
  }
}
