/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang.StringUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.w3c.dom.Document;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Parse the incoming SAML response and show the data
 *
 * @author prange
 */
@Slf4j
@Controller
@RequestMapping("/NewReceiverServlet")
public class NewReceiverServlet
{

  /**
   * Provides utility methods
   */
  private final SamlExampleHelper helper;

  /**
   * Default constructor for spring autowiring
   */
  public NewReceiverServlet(SamlExampleHelper helper)
  {
    this.helper = helper;
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

      Transformer trans = Utils.getTransformer();
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

  /**
   * The Middleware ResponseSender performs a post request with the SAML response to this endpoint
   */
  @PostMapping
  public void doPost(HttpServletRequest req, HttpServletResponse resp)
  {
    try
    {
      EidasSaml.init();
    }
    catch (InitializationException e)
    {
      log.error("Could not initialize SAML ", e);
      helper.showErrorPage(resp, "Can not initialize SAML", e.getMessage());
      return;
    }
    final SamlResult samlResult = processIncomingSAMLResponse(req);
    displayResultPage(samlResult, resp);
  }

  /**
   * This method is called when the eIDAS Middleware sent the user's browser to this servlet. The eIDAs response data is
   * extracted and the browser shows the data
   *
   * @param request The incoming HTTP request to extract the SAML and relay state data
   * @return The SamlResult containing the retrieved data or an error message
   */
  private SamlResult processIncomingSAMLResponse(HttpServletRequest request)
  {
    try
    {
      String samlResponseBase64 = request.getParameter(HttpRedirectUtils.RESPONSE_PARAMNAME);

      byte[] samlResponse = DatatypeConverter.parseBase64Binary(samlResponseBase64);

      String relayState = request.getParameter(HttpRedirectUtils.RELAYSTATE_PARAMNAME);
      return extractDataFromResponse(samlResponse, relayState);
    }
    catch (ErrorCodeException | IOException | ComponentInitializationException | XMLParserException
      | UnmarshallingException e)
    {
      log.error("Error during SAML response processing", e);
      SamlResult samlResult = new SamlResult();
      samlResult.setErrorDetails(e.getMessage());
      return samlResult;
    }
  }

  /**
   * Parse the eIDAS response return the data
   *
   * @param samlResponse The response content
   * @param relayState The value of the relay state parameter
   * @return The SAML result containing the retrieved data
   */
  private SamlResult extractDataFromResponse(byte[] samlResponse, String relayState)
    throws XMLParserException, IOException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    String saml = getXMLFromBytes(samlResponse);
    SamlResult samlResult = new SamlResult();
    samlResult.setSamlResponse(saml);
    samlResult.setRelayState(relayState);

    try (InputStream is = new ByteArrayInputStream(samlResponse))
    {
      EidasResponse resp = EidasResponse.parse(is,
                                               new X509KeyPair[]{helper.demoDecryptionKeyPair},
                                               helper.serverSigCert);
      samlResult.setLevelOfAssurance(resp.getLoa() == null ? "" : resp.getLoa().getUri());
      StringBuilder attributes = new StringBuilder();

      resp.getAttributes().forEach(e -> {
        attributes.append(e.toString());
        attributes.append("\n");
      });
      samlResult.setAttributes(attributes.toString());
    }
    return samlResult;

  }

  /**
   * Display the result in the user's browser.
   *
   * @param samlResult The SamlResult do be displayed
   * @param response response object
   */
  private void displayResultPage(SamlResult samlResult, HttpServletResponse response)
  {
    try
    {
      if (samlResult.getErrorDetails() == null)
      {
        response.setContentType("text/plain");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("Relay State: ");
        if (samlResult.getRelayState() == null)
        {
          response.getWriter().write("<null>");
        }
        else if (StringUtils.isBlank(samlResult.getRelayState()))
        {
          response.getWriter().write("<empty string>");
        }
        else
        {
          response.getWriter().write(samlResult.getRelayState());
        }
        response.getWriter().write("\n\r");
        response.getWriter().write("Level Of Assurance: ");
        response.getWriter().write(samlResult.getLevelOfAssurance());
        response.getWriter().write("\n\r");
        response.getWriter().write("\n\r");
        response.getWriter().write(samlResult.getSamlResponse());
        response.getWriter().write("\n\r");
        response.getWriter().write("\n\r");
        response.getWriter().write(samlResult.getAttributes());
      }
      else
      {
        response.getWriter().write("Error:");
        response.getWriter().write("\n\r");
        response.getWriter().write(samlResult.getErrorDetails());
      }
    }
    catch (IOException e)
    {
      log.error("Cannot show result page", e);
      response.setStatus(500);
    }
  }
}
