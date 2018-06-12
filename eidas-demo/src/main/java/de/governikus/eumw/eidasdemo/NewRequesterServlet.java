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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * This is how to send an eIDAS SAML Request in HTTP Redirect binding to the eIDAS Middleware.<br>
 * This servlet generates a eIDAS SAML Request and the user is forwarded to the eIDAS Middleware in a HTTP
 * redirect.
 *
 * @author hme
 * @author prange
 */
@Slf4j
@Controller
public class NewRequesterServlet
{

  /**
   * Provides utility methods
   */
  private final SamlExampleHelper helper;

  /**
   * Default constructor for spring autowiring
   */
  public NewRequesterServlet(SamlExampleHelper helper)
  {
    this.helper = helper;
  }

  /**
   * Start the authorisation procedure
   */
  @GetMapping("/NewRequesterServlet")
  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    byte[] samlRequest;

    // You may specify a free String of length at most 80 characters called RelayState. This value is not
    // interpreted by the server but returned unchanged with the SAML response. It is for your use only. This
    // step is optional.
    String relayState = "State#" + System.currentTimeMillis();

    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    try
    {
      EidasSaml.init();
      EidasSigner signer = new EidasSigner(true, helper.demoSignatureKey, helper.demoSignatureCertificate);

      samlRequest = EidasSaml.createRequest(Utils.createOwnUrlPrefix(request),
                                            Utils.createOwnUrlPrefix(request) + "/NewReceiverServlet",
                                            signer,
                                            reqAtt);
    }
    catch (CertificateEncodingException | ComponentInitializationException | InitializationException
      | XMLParserException | UnmarshallingException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | IOException e)
    {
      log.error("Can not create Request", e);
      helper.showErrorPage(response, "Can not create Request", e.getMessage());
      return;
    }

    try
    {
      // Create the URL used for the HTTP redirect binding. This URL sends the SAML Request to the Governikus
      // eIDAS Middleware and contains a signature generated with the demo application's private key.
      String query = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                         samlRequest,
                                                         true,
                                                         relayState,
                                                         helper.demoSignatureKey,
                                                         "SHA256");
      query += "&sessionID=" + UUID.randomUUID() + "&providerID=1";


      String html = "<!DOCTYPE html>\n" + "<html>\n" + "<body>\n" + "\n"
                    + "<a href=\"EUMWREQUESTRECEIVER\">Go to the eIDAS Middleware</a>\n" + "\n" + "</body>\n"
                    + "</html>";
      InputStream htmlStream = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
      BufferedReader reader = new BufferedReader(new InputStreamReader(htmlStream, StandardCharsets.UTF_8));

      Writer writer = response.getWriter();
      response.setContentType("text/html");
      for ( String line = reader.readLine() ; line != null ; line = reader.readLine() )
      {
        writer.write(line.replaceAll("EUMWREQUESTRECEIVER", response.encodeURL(query)));
      }
      writer.close();
    }
    catch (GeneralSecurityException | IOException e)
    {
      log.error("Can not create query URL", e);
      helper.showErrorPage(response, "Can not create query URL", e.getMessage());
    }
  }
}
