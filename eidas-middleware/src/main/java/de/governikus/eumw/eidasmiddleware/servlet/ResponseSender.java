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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.codec.binary.Hex;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import de.governikus.eumw.eidasmiddleware.WebServiceHelper;
import de.governikus.eumw.eidasmiddleware.eid.HttpServerUtils;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasEncrypter;
import de.governikus.eumw.eidasstarterkit.EidasLoA;
import de.governikus.eumw.eidasstarterkit.EidasNameId;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.EidasTransientNameId;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceFreeText;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceNo;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceStructured;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultRestrictedID;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultString;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDResultResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


/**
 * Servlet implementation class ResponseSender
 */
@WebServlet("/ResponseSender")
@Slf4j
public class ResponseSender extends HttpServlet
{

  private static final String NR = "nr";

  private static final String STREET = "street";

  private static final String REF_ID = "refID";

  private static final long serialVersionUID = 1L;

  private static final String PREFIX_ERROR = "ERROR:";

  private final SessionStore store;

  /**
   * @see HttpServlet#HttpServlet()
   */
  public ResponseSender(SessionStore store)
  {
    this.store = store;
  }

  /**
   * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
  {
    try
    {
      String refID = req.getParameter(REF_ID);
      if (refID == null)
      {
        // status code 400 should be set in case of new eID activation in TR-03130
        // version 2.0 and above.
        String errormessage = "no refid";
        resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        log.warn(errormessage);
        resp.getWriter().write(Utils.createErrorMessage(errormessage));
        return;
      }

      RequestSession samlReqSession = getSAMLReqSession(refID);
      RequestingServiceProvider reqSP = ServiceProviderConfig.getFirstProvider();
      String reqRelayState = samlReqSession.getRelayState();

      String resultMajor = req.getParameter("ResultMajor");
      if (resultMajor != null && !"ok".equals(resultMajor))
      {
        sendSAMLErrorMsg(req,
                         resp,
                         reqSP,
                         samlReqSession,
                         reqRelayState,
                         ErrorCode.EID_ERROR,
                         "ResultMajor not okay " + req.getParameter("ResultMinor"));
        return;
      }

      try
      {
        String result = runRefresh(req, resp, reqSP, reqRelayState, samlReqSession);
        if (result.startsWith(PREFIX_ERROR))
        {
          sendSAMLErrorMsg(req,
                           resp,
                           reqSP,
                           samlReqSession,
                           reqRelayState,
                           ErrorCode.INTERNAL_ERROR,
                           result.substring(6));
          return;
        }
      }
      catch (GeneralSecurityException e)
      {
        sendSAMLErrorMsg(req,
                         resp,
                         reqSP,
                         samlReqSession,
                         reqRelayState,
                         ErrorCode.EID_ERROR,
                         e.getMessage());
        return;
      }
      catch (InitializationException | ComponentInitializationException e)
      {
        sendSAMLErrorMsg(req,
                         resp,
                         reqSP,
                         samlReqSession,
                         reqRelayState,
                         ErrorCode.INTERNAL_ERROR,
                         "OpenSAML config error. Msg: " + e.getMessage());
        return;
      }
      catch (MarshallingException | TransformerFactoryConfigurationError | TransformerException
        | UnmarshallingException | XMLParserException | SignatureException | EncryptionException e)
      {
        sendSAMLErrorMsg(req,
                         resp,
                         reqSP,
                         samlReqSession,
                         reqRelayState,
                         ErrorCode.INTERNAL_ERROR,
                         "Can not create SAML response. Msg: " + e.getMessage());
        return;
      }
    }
    catch (Exception ex)
    {
      log.error(ex.getMessage(), ex);
      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      try
      {
        resp.getWriter().write(Utils.createErrorMessage("internal error in sendSAMLErrorMsg"));
      }
      catch (Exception e)
      {
        resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        log.error(e.getMessage(), e);
      }
    }
  }

  /**
   * @param refID
   * @throws ErrorCodeException
   * @throws SQLException
   */
  private RequestSession getSAMLReqSession(String refID) throws SQLException, ErrorCodeException
  {
    return store.getByEidRef(refID);
  }

  /**
   * Reform the data from the eID response to eIDAS attributes and send eIDAS SAML responses.
   *
   * @param req
   * @param resp
   * @param eIDrespInt
   */
  private void extractEIDResponceAndSendSAML(HttpServletRequest req,
                                             HttpServletResponse resp,
                                             RequestingServiceProvider reqSP,
                                             RequestSession samlReqSession,
                                             String reqRelayState,
                                             EIDResultResponse eIDrespInt)
    throws IOException, GeneralSecurityException, InitializationException, ComponentInitializationException,
    MarshallingException, TransformerFactoryConfigurationError, TransformerException, UnmarshallingException,
    XMLParserException, EncryptionException, SignatureException
  {
    ArrayList<EidasAttribute> attributes = new ArrayList<>();

    createAllNames(eIDrespInt, attributes, samlReqSession);

    EIDInfoResult dateOfBirth = eIDrespInt.getEIDInfo(EIDKeys.DATE_OF_BIRTH);
    String dateOfBirthStr = dateOfBirth instanceof EIDInfoResultString
      ? ((EIDInfoResultString)dateOfBirth).getResult() : null;
    if (dateOfBirthStr != null)
    {
      // NPA will provide only the year if birth month and/or day are unknown
      // if a month and/or day is unknown we must set the value to 00, see
      // TR-03130-3, Sec. 3.2
      String dateString = dateOfBirthStr.replace(" ", "0");
      String year = dateString.substring(0, 4);
      String month = dateString.substring(4, 6);
      String day = dateString.substring(6, 8);
      attributes.add(new DateOfBirthAttribute(year + "-" + month + "-" + day));
    }

    EIDInfoResult placeOfBirth = eIDrespInt.getEIDInfo(EIDKeys.PLACE_OF_BIRTH);
    if (placeOfBirth instanceof EIDInfoResultPlaceStructured)
    {
      attributes.add(new PlaceOfBirthAttribute(((EIDInfoResultPlaceStructured)placeOfBirth).getCity()));
    }
    else if (placeOfBirth instanceof EIDInfoResultPlaceFreeText)
    {
      attributes.add(new PlaceOfBirthAttribute(((EIDInfoResultPlaceFreeText)placeOfBirth).getFreeTextPlace()));
    }
    else if (placeOfBirth instanceof EIDInfoResultPlaceNo)
    {
      attributes.add(new PlaceOfBirthAttribute(((EIDInfoResultPlaceNo)placeOfBirth).getNoPlaceInfo()));
    }

    createPlaceOfResidence(eIDrespInt, attributes);

    EidasNameId nameId = null;
    EIDInfoResultRestrictedID restrID = (EIDInfoResultRestrictedID)eIDrespInt.getEIDInfo(EIDKeys.RESTRICTED_ID);
    if (restrID == null)
    {
      nameId = new EidasTransientNameId("PersonIdentifier not requested, therefore no NameID");
    }
    else
    {
      PersonIdentifierAttribute pi = new PersonIdentifierAttribute("DE/" + ConfigHolder.getCountryCode() + "/"
                                                                   + Hex.encodeHexString(restrID.getID1())
                                                                        .toUpperCase(Locale.GERMANY));
      attributes.add(pi);
      nameId = new EidasTransientNameId(pi.getId());
    }

    prepareSAMLResponse(req, resp, reqSP, samlReqSession, reqRelayState, attributes, nameId);
  }

  /**
   * Create FirstName and FamilyName attributes and if requested also BirthName attribute.
   *
   * @param eIDrespInt The list with the eID responses
   * @param attributes The list with the eIDAS attributes
   * @param samlReqSession
   */
  private void createAllNames(EIDResultResponse eIDrespInt,
                              List<EidasAttribute> attributes,
                              RequestSession samlReqSession)
  {
    EIDInfoResult birthName = eIDrespInt.getEIDInfo(EIDKeys.BIRTH_NAME);
    String birthNameStr = birthName instanceof EIDInfoResultString
      ? ((EIDInfoResultString)birthName).getResult() : "";
    EIDInfoResult familyNames = eIDrespInt.getEIDInfo(EIDKeys.FAMILY_NAMES);
    String familyNamesStr = familyNames instanceof EIDInfoResultString
      ? ((EIDInfoResultString)familyNames).getResult() : "";
    EIDInfoResult givenNames = eIDrespInt.getEIDInfo(EIDKeys.GIVEN_NAMES);
    String givenNamesStr = givenNames instanceof EIDInfoResultString
      ? ((EIDInfoResultString)givenNames).getResult() : "";

    // if birth name is requested, build it according to TR03130-3
    if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.BIRTH_NAME) != null)
    {
      String constructedBirthName = "";
      constructedBirthName += givenNamesStr + " ";
      if (birthName != null && StringUtil.notEmpty(birthNameStr))
      {
        constructedBirthName += birthNameStr;
      }
      else
      {
        constructedBirthName += familyNamesStr;
      }
      attributes.add(new BirthNameAttribute(constructedBirthName));
    }

    attributes.add(new FamilyNameAttribute(familyNamesStr));
    attributes.add(new GivenNameAttribute(givenNamesStr));
  }

  /**
   * Create a well defined address attribute.
   *
   * @param eIDrespInt The list with the eID responses
   * @param attributes The list with the eIDAS attributes
   */
  private void createPlaceOfResidence(EIDResultResponse eIDrespInt, List<EidasAttribute> attributes)
  {
    EIDInfoResult placeOfResidence = eIDrespInt.getEIDInfo(EIDKeys.PLACE_OF_RESIDENCE);
    if (placeOfResidence != null)
    {
      CurrentAddressAttribute cA = null;

      // handle freetextPlace (when specified)
      if (placeOfResidence instanceof EIDInfoResultPlaceStructured)
      {
        EIDInfoResultPlaceStructured pt = (EIDInfoResultPlaceStructured)placeOfResidence;
        Map<String, String> address = createStreetAndNumber(pt);
        String street = address.get(STREET);
        String nr = address.get(NR);
        String zipCode = pt.getZipCode();
        String city = pt.getCity();
        String state = pt.getState();
        String country = pt.getCountry();

        cA = new CurrentAddressAttribute(nr, street, city, zipCode, null, null, null, country, state);
      }
      else if (placeOfResidence instanceof EIDInfoResultPlaceNo)
      {
        cA = new CurrentAddressAttribute();
      }
      attributes.add(cA);
    }
  }

  /**
   * Separates the street from the number of an address, if number exists.
   *
   * @param pt
   * @return
   */
  private Map<String, String> createStreetAndNumber(EIDInfoResultPlaceStructured pt)
  {
    Map<String, String> result = new HashMap<>();
    if (pt.getStreet() != null)
    {
      int idx = -1;
      String s = pt.getStreet().trim();
      // try to find the steet nr in the street string
      for ( int i = 0 ; i < s.length() ; i++ )
      {
        if (Character.isDigit(s.charAt(i)))
        {
          idx = i;
          break;
        }
      }

      if (idx > 0)
      {
        result.put(STREET, s.substring(0, idx).trim());
        result.put(NR, s.substring(idx).trim());
      }
      else
      {
        result.put(STREET, s);
        result.put(NR, "");
      }
    }
    return result;
  }

  /**
   * Create a SAML response from the attribute list and redirect to the service provider consumer URL.
   *
   * @param req
   * @param resp
   * @param attributes
   * @param nameId
   */
  private void prepareSAMLResponse(HttpServletRequest req,
                                   HttpServletResponse resp,
                                   RequestingServiceProvider reqSP,
                                   RequestSession samlReqSession,
                                   String reqRelayState,
                                   ArrayList<EidasAttribute> attributes,
                                   EidasNameId nameId)
    throws IOException, GeneralSecurityException, InitializationException, XMLParserException,
    UnmarshallingException, EncryptionException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException, ComponentInitializationException
  {
    String serverurl = Utils.getMiddlewareServiceEntityId(req);

    EidasSigner signer = new EidasSigner(true, ConfigHolder.getAppSignatureKeyPair().getKey(),
                                         ConfigHolder.getAppSignatureKeyPair().getCert());
    EidasEncrypter encrypter = new EidasEncrypter(true, reqSP.getEncryptionCert());

    byte[] eidasResp = EidasSaml.createResponse(attributes,
                                                reqSP.getAssertionConsumerURL(),
                                                reqSP.getEntityID(),
                                                nameId,
                                                serverurl,
                                                EidasLoA.HIGH,
                                                samlReqSession.getReqId(),
                                                encrypter,
                                                signer);
    String content = WebServiceHelper.createForwardToConsumer(eidasResp, reqRelayState, null);

    HttpServerUtils.setPostContent(content, reqSP.getAssertionConsumerURL(), null, resp);
  }

  /**
   * Runs stuff for refresh page specified in Object Tag. This methods is only needed if the refresh page is
   * in this application and not on the eID-Server. The refresh page is shown while the AusweisApp runs and in
   * case something went wrong and the application did not get a real response from the AusweisApp it should
   * check for a response from the server. The first time we wait 15 second as it takes at least that time to
   * read some attributes from the nPA and then it checks every 4 seconds. <br/>
   * We have to increase the request counter in every request the poseidas server will reject a request with a
   * request counter equal or less than the previous one.
   *
   * @return html to show.
   * @throws IOException
   * @throws GeneralSecurityException
   * @throws JAXBException
   * @throws UnmarshallingException
   * @throws TransformerException
   * @throws TransformerFactoryConfigurationError
   * @throws MarshallingException
   * @throws SignatureException
   * @throws EncryptionException
   * @throws XMLParserException
   */
  private String runRefresh(HttpServletRequest req,
                            HttpServletResponse resp,
                            RequestingServiceProvider reqSP,
                            String reqRelayState,
                            RequestSession samlReqSession)
    throws GeneralSecurityException, IOException, InitializationException, ComponentInitializationException,
    MarshallingException, TransformerFactoryConfigurationError, TransformerException, UnmarshallingException,
    XMLParserException, EncryptionException, SignatureException
  {
    HttpSession session = req.getSession();
    String refID = req.getParameter(REF_ID);
    // Get the last request counter value
    Integer lastRequestCounter = (Integer)session.getAttribute("lastRequestCounter");
    int requestCounter;
    if (lastRequestCounter == null)
    {
      session.setAttribute(REF_ID, refID);
      requestCounter = 0;
    }
    else
    {
      requestCounter = lastRequestCounter.intValue() + 1;
    }
    session.setAttribute("lastRequestCounter", Integer.valueOf(requestCounter));

    EIDResultResponse eidResponse = EIDInternal.getInstance().getResult(refID, requestCounter);

    if (WebServiceHelper.checkResult(eidResponse.getResult(), Constants.EID_MAJOR_OK, null))
    {
      session.invalidate();
      extractEIDResponceAndSendSAML(req, resp, reqSP, samlReqSession, reqRelayState, eidResponse);
      return "OKAY";
    }
    else if (WebServiceHelper.checkResult(eidResponse.getResult(),
                                          Constants.EID_MAJOR_ERROR,
                                          Constants.EID_MINOR_GETRESULT_NO_RESULT_YET))
    {
      if (requestCounter == 0)
      {
        // We are in the first request, when the old eID-Activation is used it takes
        // some time till the user
        // authenticated with the AusweisApp, so we wait 15 seconds. With the enw
        // eID-activation this servlet
        // will be called when the authentication is finished.
        return showRefresh(15);
      }
      else
      {
        // no result available, we will try again in 4 seconds.
        return showRefresh(4);
      }
    }
    return PREFIX_ERROR + eidResponse.getResult().getResultMinor();
  }

  /**
   * Show refresh page.
   *
   * @param refreshTime time to wait for next request in seconds.
   * @return html to show.
   * @throws IOException
   */
  private String showRefresh(int refreshTime) throws IOException
  {
    return Utils.readFromStream(WebServiceHelper.class.getResourceAsStream("refresh.html"))
                .replace("#{REFRESH_TIME}", Integer.toString(refreshTime));
  }

  private String requestInfo(RequestingServiceProvider reqSP, String reqRelayState)
  {
    return " Error in request for SPname " + reqSP.getEntityID() + " consumerUrl "
           + reqSP.getAssertionConsumerURL() + " relayState " + reqRelayState + " ";
  }

  private void sendSAMLErrorMsg(HttpServletRequest req,
                                HttpServletResponse response,
                                RequestingServiceProvider reqSP,
                                RequestSession samlReqSession,
                                String reqRelayState,
                                ErrorCode error,
                                String... msg)
  {
    log.warn(requestInfo(reqSP, reqRelayState));
    log.warn(error.toDescription(msg));
    response.setStatus(400);
    String serverurl = Utils.getMiddlewareServiceEntityId(req);
    EidasSigner signer;
    try
    {
      signer = new EidasSigner(true, ConfigHolder.getAppSignatureKeyPair().getKey(),
                               ConfigHolder.getAppSignatureKeyPair().getCert());
      EidasResponse rsp = new EidasResponse(reqSP.getAssertionConsumerURL(), reqSP.getEntityID(),
                                            null, samlReqSession.getReqId(), serverurl, EidasLoA.HIGH, signer,
                                            null);
      byte[] eidasResp = rsp.generateErrorRsp(error, msg);
      String content = WebServiceHelper.createForwardToConsumer(eidasResp, reqRelayState, null);
      HttpServerUtils.setPostContent(content, reqSP.getAssertionConsumerURL(), null, response);
      return;
    }
    catch (IOException | GeneralSecurityException | XMLParserException | UnmarshallingException
      | MarshallingException | SignatureException | TransformerFactoryConfigurationError
      | TransformerException | ComponentInitializationException e)
    {
      log.warn(e.getMessage(), e);
      try
      {
        response.getWriter().write(Utils.createErrorMessage("internal error in sendSAMLErrorMsg"));
      }
      catch (IOException e1)
      {
        log.warn(e1.getMessage(), e1);
      }
      return;
    }
  }

  /**
   * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
  {
    log.warn("Some send me a POST message but i only can consume GET messages!");
  }
}
