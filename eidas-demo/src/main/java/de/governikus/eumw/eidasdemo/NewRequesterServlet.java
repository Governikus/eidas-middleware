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

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;

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
 * This is how to send aeIDAS SAML Request in HTTP Redirect binding to the eIDAS Middleware.<br>
 * This servlet generates a eIDAS SAML Request and the user is forwarded to the eIDAS Middleware in a HTTP
 * redirect. <br>
 * The URL this Sevlet is deployed under must match the same origin of the subject URL in the CVC description
 * (Beschreibung des Berechtigungszertifikats).
 * 
 * @author hme
 * @author prange
 */
@Slf4j
@WebServlet("/NewRequesterServlet")
public class NewRequesterServlet extends HttpServlet
{

  /**
   * Provides utility methods
   */
  private final SamlExampleHelper helper;

  /**
   * This field has nothing to do with SAML: see JAVA doc for meaning
   */
  private static final long serialVersionUID = 1L;

  /**
   * Default constructor for spring autowiring
   */
  @Autowired
  public NewRequesterServlet(SamlExampleHelper helper)
  {
    this.helper = helper;
  }


  /**
   * This method is called when a get request for this servlet arrives at the server. It creates a SAML
   * request and displays a link for the user to get redirected to the eIDAS Middleware.
   * 
   * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
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
      // poseidas and contains a signature with the Service providers private key over this Request and an
      // additional parameter. The SAML request is base64 encoded any inflated.
      String query = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                         samlRequest,
                                                         true,
                                                         relayState,
                                                         helper.demoSignatureKey,
                                                         "SHA256");
      query += "&sessionID=" + UUID.randomUUID() + "&providerID=1";


      String html = "<!DOCTYPE html>\n" + "<html>\n" + "<body>\n" + "\n"
                    + "<a href=\"EUMWREQUESTRECEIVER\">Go to the eu middleware</a>\n" + "\n" + "</body>\n"
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
