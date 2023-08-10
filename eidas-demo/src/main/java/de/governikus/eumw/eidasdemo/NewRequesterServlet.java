/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

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
  public ModelAndView doGet(HttpServletRequest httpServletRequest)
  {
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
    reqAtt.put(EidasNaturalPersonAttributes.NATIONALITY, true);


    ModelAndView requestPage = new ModelAndView("NewRequesterServlet");
    try
    {
      EidasSaml.init();
      EidasSigner signer = new EidasSigner(true, helper.demoSignatureKey, helper.demoSignatureCertificate);

      requestPage.addObject("relayState", relayState);
      requestPage.addObject("receiverUrl", helper.serverSamlReceiverUrl);

      final String ownURL = httpServletRequest.getRequestURL().toString();
      String issuerUrl = ownURL.replace("NewRequesterServlet", "Metadata");
      String destinationUrl = helper.serverSamlReceiverUrl;

      addNormalRedirectRequests(requestPage, issuerUrl, destinationUrl, reqAtt, relayState);

      addNormalPostRedirectRequest(requestPage, issuerUrl, destinationUrl, reqAtt, signer);

      addSPTypeRequests(requestPage, issuerUrl, destinationUrl, reqAtt, relayState);

      addTestRequests(requestPage, issuerUrl, destinationUrl, reqAtt, relayState);

      return requestPage;
    }
    catch (Exception e)
    {
      log.error("Can not create query URL", e);
      ModelAndView error = new ModelAndView("Error");
      error.addObject("errorCode", "Cannot prepare SAML requests");
      error.addObject("details", e.getMessage());
      return error;
    }
  }

  private void addTestRequests(ModelAndView requestPage,
                               String issuerUrl,
                               String destinationUrl,
                               HashMap<EidasPersonAttributes, Boolean> reqAtt,
                               String relayState)
    throws Exception
  {
    byte[] samlTestRequest = EidasSaml.createRequest(issuerUrl,
                                                     destinationUrl,
                                                     null,
                                                     reqAtt,
                                                     null,
                                                     EidasNameIdType.TRANSIENT,
                                                     EidasLoaEnum.LOA_TEST);
    byte[] samlTestRequestCancellationByUser = EidasSaml.createRequest(issuerUrl,
                                                                       destinationUrl,
                                                                       null,
                                                                       reqAtt,
                                                                       null,
                                                                       EidasNameIdType.TRANSIENT,
                                                                       EidasLoaEnum.LOA_TEST,
                                                                       TestCaseEnum.CANCELLATION_BY_USER);
    byte[] samlTestRequestWrongPin = EidasSaml.createRequest(issuerUrl,
                                                             destinationUrl,
                                                             null,
                                                             reqAtt,
                                                             null,
                                                             EidasNameIdType.TRANSIENT,
                                                             EidasLoaEnum.LOA_TEST,
                                                             TestCaseEnum.WRONG_PIN);
    byte[] samlTestRequestWrongSignature = EidasSaml.createRequest(issuerUrl,
                                                                   destinationUrl,
                                                                   null,
                                                                   reqAtt,
                                                                   null,
                                                                   EidasNameIdType.TRANSIENT,
                                                                   EidasLoaEnum.LOA_TEST,
                                                                   TestCaseEnum.WRONG_SIGNATURE);
    byte[] samlTestRequestCardExpired = EidasSaml.createRequest(issuerUrl,
                                                                destinationUrl,
                                                                null,
                                                                reqAtt,
                                                                null,
                                                                EidasNameIdType.TRANSIENT,
                                                                EidasLoaEnum.LOA_TEST,
                                                                TestCaseEnum.CARD_EXPIRED);
    byte[] samlTestRequestUnknown = EidasSaml.createRequest(issuerUrl,
                                                            destinationUrl,
                                                            null,
                                                            reqAtt,
                                                            null,
                                                            EidasNameIdType.TRANSIENT,
                                                            EidasLoaEnum.LOA_TEST,
                                                            TestCaseEnum.UNKNOWN);

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

    requestPage.addObject("queryTestRequest", queryTestRequest);
    requestPage.addObject("queryTestRequestCancellationByUser", queryTestRequestCancellationByUser);
    requestPage.addObject("queryTestRequestWrongPin", queryTestRequestWrongPin);
    requestPage.addObject("queryTestRequestWrongSignature", queryTestRequestWrongSignature);
    requestPage.addObject("queryTestRequestCardExpired", queryTestRequestCardExpired);
    requestPage.addObject("queryTestRequestUnknown", queryTestRequestUnknown);
  }

  private void addSPTypeRequests(ModelAndView requestPage,
                                 String issuerUrl,
                                 String destinationUrl,
                                 HashMap<EidasPersonAttributes, Boolean> reqAtt,
                                 String relayState)
    throws Exception
  {
    byte[] samlRequestPublicSP = EidasSaml.createRequest(issuerUrl,
                                                         destinationUrl,
                                                         null,
                                                         reqAtt,
                                                         SPTypeEnumeration.PUBLIC,
                                                         EidasNameIdType.TRANSIENT,
                                                         EidasLoaEnum.LOA_HIGH);
    byte[] samlRequestPrivateSP = EidasSaml.createRequest(issuerUrl,
                                                          destinationUrl,
                                                          "providerName",
                                                          "providerB",
                                                          null,
                                                          reqAtt,
                                                          SPTypeEnumeration.PRIVATE,
                                                          EidasNameIdType.TRANSIENT,
                                                          EidasLoaEnum.LOA_HIGH);

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

    requestPage.addObject("requestPublicSP", queryPublicSP);
    requestPage.addObject("requestPrivateSP", queryPrivateSP);
  }

  private void addNormalPostRedirectRequest(ModelAndView requestPage,
                                            String issuerUrl,
                                            String destinationUrl,
                                            HashMap<EidasPersonAttributes, Boolean> reqAtt,
                                            EidasSigner signer)
    throws Exception
  {

    byte[] samlPostRequest = EidasSaml.createRequest(issuerUrl,
                                                     destinationUrl,
                                                     signer,
                                                     reqAtt,
                                                     null,
                                                     EidasNameIdType.TRANSIENT,
                                                     EidasLoaEnum.LOA_HIGH);
    requestPage.addObject("postRequest", Base64.getEncoder().encodeToString(samlPostRequest));
  }

  private void addNormalRedirectRequests(ModelAndView requestPage,
                                         String issuerUrl,
                                         String destinationUrl,
                                         Map<EidasPersonAttributes, Boolean> reqAtt,
                                         String relayState)
    throws Exception
  {
    byte[] samlRedirectRequest = EidasSaml.createRequest(issuerUrl,
                                                         destinationUrl,
                                                         null,
                                                         reqAtt,
                                                         null,
                                                         EidasNameIdType.TRANSIENT,
                                                         EidasLoaEnum.LOA_HIGH);

    // Create the URL used for the HTTP redirect binding. This URL sends the SAML Request to the Governikus
    // eIDAS Middleware and contains a signature generated with the demo application's private key.
    String withRelayState = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                samlRedirectRequest,
                                                                true,
                                                                relayState,
                                                                helper.demoSignatureKey,
                                                                "SHA256");

    String emptyRelayState = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                 samlRedirectRequest,
                                                                 true,
                                                                 "",
                                                                 helper.demoSignatureKey,
                                                                 "SHA256");

    String withoutRelayState = HttpRedirectUtils.createQueryString(helper.serverSamlReceiverUrl,
                                                                   samlRedirectRequest,
                                                                   true,
                                                                   null,
                                                                   helper.demoSignatureKey,
                                                                   "SHA256");

    requestPage.addObject("redirectWithRelayState", withRelayState);
    requestPage.addObject("redirectEmptyRelayState", emptyRelayState);
    requestPage.addObject("redirectWithoutRelayState", withoutRelayState);
  }
}
