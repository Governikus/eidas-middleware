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
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.DatatypeConverter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
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

      return bout.toString(Utils.ENCODING);
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
  public ModelAndView doPost(HttpServletRequest req)
  {
    try
    {
      final SamlResult samlResult = processIncomingSAMLResponse(req);
      return displayResultPage(samlResult);
    }
    catch (Exception e)
    {
      log.error("Could not process SAML response", e);
      ModelAndView error = new ModelAndView("Error");
      error.addObject("errorCode", "Could not process SAML response");
      error.addObject("details", e.getMessage());
      return error;
    }
  }

  /**
   * This method is called when the eIDAS Middleware sent the user's browser to this servlet. The eIDAs response data is
   * extracted and the browser shows the data
   *
   * @param request The incoming HTTP request to extract the SAML and relay state data
   * @return The SamlResult containing the retrieved data or an error message
   */
  private SamlResult processIncomingSAMLResponse(HttpServletRequest request) throws Exception
  {
    String samlResponseBase64 = request.getParameter(HttpRedirectUtils.RESPONSE_PARAMNAME);

    byte[] samlResponse = DatatypeConverter.parseBase64Binary(samlResponseBase64);

    String relayState = request.getParameter(HttpRedirectUtils.RELAYSTATE_PARAMNAME);
    return extractDataFromResponse(samlResponse, relayState);
  }

  /**
   * Parse the eIDAS response return the data
   *
   * @param samlResponse The response content
   * @param relayState The value of the relay state parameter
   * @return The SAML result containing the retrieved data
   */
  private SamlResult extractDataFromResponse(byte[] samlResponse, String relayState)
    throws XMLParserException, IOException, UnmarshallingException, ErrorCodeException,
    ComponentInitializationException, MarshallingException, TransformerException
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
      samlResult.setLevelOfAssurance(resp.getLoa() == null ? null : resp.getLoa().getUri());
      samlResult.setAttributes(resp.getAttributes());
      if (resp.getOpenSamlResponse().getAssertions().size() == 1)
      {
        Element assertionElement = new AssertionMarshaller().marshall(resp.getOpenSamlResponse()
                                                                          .getAssertions()
                                                                          .get(0));
        Transformer transformer = Utils.getTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(assertionElement), new StreamResult(outputStream));
        samlResult.setAssertion(outputStream.toString(StandardCharsets.UTF_8));
      }
    }
    return samlResult;

  }

  /**
   * Display the result in the user's browser.
   *
   * @param samlResult The SamlResult do be displayed
   */
  private ModelAndView displayResultPage(SamlResult samlResult)
  {
    ModelAndView resultPage = new ModelAndView("NewReceiverServlet");
    if (samlResult.getErrorDetails() == null)
    {
      if (samlResult.getRelayState() == null)
      {
        resultPage.addObject("relayState", "<null>");
      }
      else if (StringUtils.isBlank(samlResult.getRelayState()))
      {
        resultPage.addObject("relayState", "<empty string>");
      }
      else
      {
        resultPage.addObject("relayState", samlResult.getRelayState());
      }
      resultPage.addObject("levelOfAssurance", samlResult.getLevelOfAssurance());
      resultPage.addObject("samlResponse", samlResult.getSamlResponse());
      resultPage.addObject("samlResult",
                           samlResult.getAttributes()
                                     .stream()
                                     .collect(Collectors.toMap(eidasAttribute -> eidasAttribute.type()
                                                                                               .getFriendlyName(),
                                                               EidasAttribute::getValue)));
      resultPage.addObject("samlAssertion", samlResult.getAssertion());
    }
    else
    {
      resultPage.addObject("relayState", samlResult.getErrorDetails());
    }
    return resultPage;
  }
}
