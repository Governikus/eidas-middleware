/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.io.IOUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.TestCaseEnum;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.extern.slf4j.Slf4j;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;


/**
 * This is how to send an eIDAS SAML Request in HTTP Redirect binding to the eIDAS Middleware.<br>
 * This servlet generates a eIDAS SAML Request and the user is forwarded to the eIDAS Middleware in a HTTP redirect.
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
    byte[] samlRequestPublicSP;
    byte[] samlRequestPrivateSP;
    byte[] samlTestRequest;
    byte[] samlTestRequestCancellationByUser;
    byte[] samlTestRequestWrongPin;
    byte[] samlTestRequestWrongSignature;
    byte[] samlTestRequestCardExpired;
    byte[] samlTestRequestUnknown;

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

      final String ownURL = request.getRequestURL().toString();
      samlRequest = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                            ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                            signer,
                                            reqAtt,
                                            null,
                                            EidasNameIdType.TRANSIENT,
                                            EidasLoaEnum.LOA_HIGH);
      samlRequestPublicSP = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                    ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                    signer,
                                                    reqAtt,
                                                    SPTypeEnumeration.PUBLIC,
                                                    EidasNameIdType.TRANSIENT,
                                                    EidasLoaEnum.LOA_HIGH);
      samlRequestPrivateSP = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                     ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                     "providerName",
                                                     "providerB",
                                                     signer,
                                                     reqAtt,
                                                     SPTypeEnumeration.PRIVATE,
                                                     EidasNameIdType.TRANSIENT,
                                                     EidasLoaEnum.LOA_HIGH);
      samlTestRequest = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                signer,
                                                reqAtt,
                                                null,
                                                EidasNameIdType.TRANSIENT,
                                                EidasLoaEnum.LOA_TEST);
      samlTestRequestCancellationByUser = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                                  ownURL.replace("NewRequesterServlet",
                                                                                 "NewReceiverServlet"),
                                                                  signer,
                                                                  reqAtt,
                                                                  null,
                                                                  EidasNameIdType.TRANSIENT,
                                                                  EidasLoaEnum.LOA_TEST,
                                                                  TestCaseEnum.CANCELLATION_BY_USER);
      samlTestRequestWrongPin = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                        ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                        signer,
                                                        reqAtt,
                                                        null,
                                                        EidasNameIdType.TRANSIENT,
                                                        EidasLoaEnum.LOA_TEST,
                                                        TestCaseEnum.WRONG_PIN);
      samlTestRequestWrongSignature = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                              ownURL.replace("NewRequesterServlet",
                                                                             "NewReceiverServlet"),
                                                              signer,
                                                              reqAtt,
                                                              null,
                                                              EidasNameIdType.TRANSIENT,
                                                              EidasLoaEnum.LOA_TEST,
                                                              TestCaseEnum.WRONG_SIGNATURE);
      samlTestRequestCardExpired = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                           ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                           signer,
                                                           reqAtt,
                                                           null,
                                                           EidasNameIdType.TRANSIENT,
                                                           EidasLoaEnum.LOA_TEST,
                                                           TestCaseEnum.CARD_EXPIRED);
      samlTestRequestUnknown = EidasSaml.createRequest(ownURL.replace("NewRequesterServlet", "Metadata"),
                                                       ownURL.replace("NewRequesterServlet", "NewReceiverServlet"),
                                                       signer,
                                                       reqAtt,
                                                       null,
                                                       EidasNameIdType.TRANSIENT,
                                                       EidasLoaEnum.LOA_TEST,
                                                       TestCaseEnum.UNKNOWN);
    }
    catch (CertificateEncodingException | InitializationException | MarshallingException | SignatureException
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

      String emptyRelayState = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                   samlRequest,
                                                                   true,
                                                                   "",
                                                                   helper.demoSignatureKey,
                                                                   "SHA256");
      String withoutRelayState = emptyRelayState.replace("&RelayState=", "");

      String queryPublicSP = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                 samlRequestPublicSP,
                                                                 true,
                                                                 relayState,
                                                                 helper.demoSignatureKey,
                                                                 "SHA256");
      String queryPrivateSP = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                  samlRequestPrivateSP,
                                                                  true,
                                                                  relayState,
                                                                  helper.demoSignatureKey,
                                                                  "SHA256");

      String queryTestRequest = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                    samlTestRequest,
                                                                    true,
                                                                    relayState,
                                                                    helper.demoSignatureKey,
                                                                    "SHA256");

      String queryTestRequestCancellationByUser = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                                      samlTestRequestCancellationByUser,
                                                                                      true,
                                                                                      relayState,
                                                                                      helper.demoSignatureKey,
                                                                                      "SHA256");

      String queryTestRequestWrongPin = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                            samlTestRequestWrongPin,
                                                                            true,
                                                                            relayState,
                                                                            helper.demoSignatureKey,
                                                                            "SHA256");

      String queryTestRequestWrongSignature = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                                  samlTestRequestWrongSignature,
                                                                                  true,
                                                                                  relayState,
                                                                                  helper.demoSignatureKey,
                                                                                  "SHA256");

      String queryTestRequestCardExpired = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                               samlTestRequestCardExpired,
                                                                               true,
                                                                               relayState,
                                                                               helper.demoSignatureKey,
                                                                               "SHA256");

      String queryTestRequestUnknown = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                           samlTestRequestUnknown,
                                                                           true,
                                                                           relayState,
                                                                           helper.demoSignatureKey,
                                                                           "SHA256");

      String html = IOUtils.toString(this.getClass().getResourceAsStream("/NewRequesterServlet.html"),
                                     StandardCharsets.UTF_8);
      html = html.replace("DEFAULTREQUEST", query);
      html = html.replace("CURRENTRELAYSTATE", relayState);
      html = html.replace("EMPTYRELAYSTATE", emptyRelayState);
      html = html.replace("WITHOUTRELAYSTATE", withoutRelayState);
      html = html.replace("REQUESTPUBLICSP", queryPublicSP);
      html = html.replace("REQUESTPRIVATESP", queryPrivateSP);
      html = html.replace("TESTREQUEST", queryTestRequest);
      html = html.replace("CANCELLATIONBYUSER", queryTestRequestCancellationByUser);
      html = html.replace("WRONGPIN", queryTestRequestWrongPin);
      html = html.replace("WRONGSIGNATURE", queryTestRequestWrongSignature);
      html = html.replace("CARDEXPIRED", queryTestRequestCardExpired);
      html = html.replace("UNKNOWN", queryTestRequestUnknown);


      Writer writer = response.getWriter();
      response.setContentType("text/html");
      writer.write(html);
      writer.close();
    }
    catch (GeneralSecurityException | IOException e)
    {
      log.error("Can not create query URL", e);
      helper.showErrorPage(response, "Can not create query URL", e.getMessage());
    }
  }
}
