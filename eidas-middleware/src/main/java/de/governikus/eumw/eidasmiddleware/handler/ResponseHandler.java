/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.handler;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;
import javax.xml.transform.TransformerException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.stereotype.Service;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import de.governikus.eumw.eidasmiddleware.WebServiceHelper;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasEncrypter;
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
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultDeselected;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultNotOnChip;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceFreeText;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceNo;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceStructured;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultRestrictedID;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultString;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDResultResponse;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.common.EidasLoaEnum;


/**
 * Handle the incoming redirect from the Ausweisapp2. Check for eID errors or gather the received data from
 * the eID card and prepare the SAML response.
 */
@Slf4j
@Service
public class ResponseHandler
{

  private static final String REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED = "Required attribute has been deselected";

  private static final String UNKNOWN_REF_ID = "Unknown refID";

  private static final String NR = "nr";

  private static final String STREET = "street";

  private final SessionStore sessionStore;

  private final ConfigHolder configHolder;

  private final ServiceProviderConfig serviceProviderConfig;

  private final HSMServiceHolder hsmServiceHolder;

  private final EIDInternal eidInternal;

  public ResponseHandler(SessionStore sessionStore,
                         ConfigHolder configHolder,
                         ServiceProviderConfig serviceProviderConfig,
                         HSMServiceHolder hsmServiceHolder,
                         EIDInternal eidInternal)
  {
    this.sessionStore = sessionStore;
    this.configHolder = configHolder;
    this.serviceProviderConfig = serviceProviderConfig;
    this.hsmServiceHolder = hsmServiceHolder;
    this.eidInternal = eidInternal;
  }

  private RequestSession getSAMLReqSession(String refID)
  {
    try
    {
      return sessionStore.getByEidRef(refID);
    }
    catch (SQLException | ErrorCodeException e)
    {
      log.error("Cannot get request session for refID: {}", refID);
      return null;
    }
  }

  /**
   * Get the SAML response string for this refID
   *
   * @param refID The refID that was sent from the AusweisApp2
   * @return The SAML response, already encrypted if necessary, signed and base64 encoded
   */
  public String getResultForRefID(String refID)
  {
    RequestSession samlReqSession = getSAMLReqSession(refID);
    if (samlReqSession == null)
    {
      throw new RequestProcessingException(UNKNOWN_REF_ID);
    }
    RequestingServiceProvider reqSP = serviceProviderConfig.getProviderByEntityID(samlReqSession.getReqProviderEntityId());

    EIDResultResponse eidResponse = eidInternal.getResult(refID, 0);
    if (WebServiceHelper.checkResult(eidResponse.getResult(), Constants.EID_MAJOR_OK, null))
    {
      String response;
      try
      {
        response = prepareSAMLResponse(reqSP, samlReqSession, eidResponse);
      }
      catch (RequestProcessingException e)
      {
        response = prepareSAMLErrorResponse(reqSP,
                                            samlReqSession.getReqId(),
                                            ErrorCode.INTERNAL_ERROR,
                                            e.getMessage());
      }
      return response;
    }
    else
    {
      if (WebServiceHelper.checkResult(eidResponse.getResult(),
                                       Constants.EID_MAJOR_ERROR,
                                       ResultMinor.SAL_CANCELLATION_BY_USER.toString()))
      {
        return prepareSAMLErrorResponse(reqSP,
                                        samlReqSession.getReqId(),
                                        ErrorCode.CANCELLATION_BY_USER,
                                        eidResponse.getResultMessage());
      }
      else
      {
        String message;
        if (StringUtils.isNotBlank(eidResponse.getResultMessage()))
        {
          message = eidResponse.getResultMessage();
        }
        else
        {
          message = eidResponse.getResultMinor();
        }
        return prepareSAMLErrorResponse(reqSP, samlReqSession.getReqId(), ErrorCode.EID_ERROR, message);
      }
    }
  }

  public String prepareSAMLErrorResponse(RequestingServiceProvider reqSP,
                                            String samlReqId,
                                            ErrorCode errorCode,
                                            String... msg)
  {
    log.warn(prepareLogMessage(reqSP, samlReqId, errorCode.toDescription(msg)));
    try
    {
      EidasSigner signer = getEidasSigner();
      EidasResponse rsp = new EidasResponse(reqSP.getAssertionConsumerURL(), reqSP.getEntityID(), null,
                                            samlReqId,
                                            configHolder.getServerURLWithContextPath()
                                                       + ContextPaths.METADATA,
                                            EidasLoaEnum.LOA_HIGH, signer, null);
      byte[] eidasResp = rsp.generateErrorRsp(errorCode, msg);
      return DatatypeConverter.printBase64Binary(eidasResp);
    }
    catch (IOException | GeneralSecurityException | MarshallingException | SignatureException
      | TransformerException e)
    {
      throw new RequestProcessingException("Cannot create SAML response", e);
    }
  }

  private EidasSigner getEidasSigner() throws IOException, GeneralSecurityException
  {
    EidasSigner signer;
    if (hsmServiceHolder.getKeyStore() == null)
    {
      signer = new EidasSigner(true, configHolder.getAppSignatureKeyPair().getKey(),
                               configHolder.getAppSignatureKeyPair().getCert());
    }
    else
    {
      signer = new EidasSigner(hsmServiceHolder.getKeyStore());
    }
    return signer;
  }

  private String prepareLogMessage(RequestingServiceProvider reqSP,
                                   String samlRequestId,
                                   String errorCodeDescription)
  {
    StringBuilder result = new StringBuilder();
    result.append("Error in request for SPname: '")
          .append(reqSP.getEntityID())
          .append("' and consumerUrl: '")
          .append(reqSP.getAssertionConsumerURL())
          .append("' and SAML request id:' ")
          .append(samlRequestId)
          .append("'. Error: ")
          .append(errorCodeDescription);
    return result.toString();
  }

  protected String prepareSAMLResponse(RequestingServiceProvider reqSP,
                                       RequestSession samlReqSession,
                                       EIDResultResponse eidResponse)
  {
    ArrayList<EidasAttribute> attributes = new ArrayList<>();

    if (!createAllNames(eidResponse, attributes, samlReqSession))
    {
      return prepareSAMLErrorResponse(reqSP,
                                      samlReqSession.getReqId(),
                                      ErrorCode.AUTHORIZATION_FAILED,
                                      REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED);
    }

    EIDInfoResult dateOfBirth = eidResponse.getEIDInfo(EIDKeys.DATE_OF_BIRTH);
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
    else if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.DATE_OF_BIRTH) != null
             && samlReqSession.getRequestedAttributes()
                              .get(EidasNaturalPersonAttributes.DATE_OF_BIRTH)
                              .booleanValue())
    {
      return prepareSAMLErrorResponse(reqSP,
                                      samlReqSession.getReqId(),
                                      ErrorCode.AUTHORIZATION_FAILED,
                                      REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED);
    }

    EIDInfoResult placeOfBirth = eidResponse.getEIDInfo(EIDKeys.PLACE_OF_BIRTH);
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
    else if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.PLACE_OF_BIRTH) != null
             && samlReqSession.getRequestedAttributes()
                              .get(EidasNaturalPersonAttributes.PLACE_OF_BIRTH)
                              .booleanValue())
    {
      return prepareSAMLErrorResponse(reqSP,
                                      samlReqSession.getReqId(),
                                      ErrorCode.AUTHORIZATION_FAILED,
                                      REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED);
    }

    if (!createPlaceOfResidence(eidResponse, attributes, samlReqSession))
    {
      return prepareSAMLErrorResponse(reqSP,
                                      samlReqSession.getReqId(),
                                      ErrorCode.AUTHORIZATION_FAILED,
                                      REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED);
    }

    EidasNameId nameId;
    EIDInfoResultRestrictedID restrID = (EIDInfoResultRestrictedID)eidResponse.getEIDInfo(EIDKeys.RESTRICTED_ID);
    if (restrID == null)
    {
      if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.PERSON_IDENTIFIER) != null
          && samlReqSession.getRequestedAttributes()
                           .get(EidasNaturalPersonAttributes.PERSON_IDENTIFIER)
                           .booleanValue())
      {
        return prepareSAMLErrorResponse(reqSP,
                                        samlReqSession.getReqId(),
                                        ErrorCode.AUTHORIZATION_FAILED,
                                        REQUIRED_ATTRIBUTE_HAS_BEEN_DESELECTED);
      }
      nameId = new EidasTransientNameId("PersonIdentifier not requested, therefore no NameID");
    }
    else
    {
      PersonIdentifierAttribute pi = new PersonIdentifierAttribute("DE/" + configHolder.getCountryCode() + "/"
                                                                   + Hex.encodeHexString(restrID.getID1())
                                                                        .toUpperCase(Locale.GERMANY));
      attributes.add(pi);
      nameId = new EidasTransientNameId(pi.getValue());
    }


    try
    {
      EidasSigner signer = getEidasSigner();

      EidasEncrypter encrypter = new EidasEncrypter(true, reqSP.getEncryptionCert());

      byte[] eidasResp = EidasSaml.createResponse(attributes,
                                                  reqSP.getAssertionConsumerURL(),
                                                  reqSP.getEntityID(),
                                                  nameId,
                                                  configHolder.getServerURLWithContextPath()
                                                          + ContextPaths.METADATA,
                                                  EidasLoaEnum.LOA_HIGH,
                                                  samlReqSession.getReqId(),
                                                  encrypter,
                                                  signer);
      return DatatypeConverter.printBase64Binary(eidasResp);
    }
    catch (IOException | GeneralSecurityException | InitializationException | XMLParserException
      | EncryptionException | MarshallingException | SignatureException | TransformerException e)
    {
      throw new RequestProcessingException("Cannot create SAML response", e);
    }
  }

  /**
   * Create FirstName and FamilyName attributes and if requested also BirthName attribute.
   *
   * @param eIDrespInt The list with the eID responses
   * @param attributes The list with the eIDAS attributes
   * @param samlReqSession The original SAML request
   */
  protected boolean createAllNames(EIDResultResponse eIDrespInt,
                                   List<EidasAttribute> attributes,
                                   RequestSession samlReqSession)
  {
    EIDInfoResult birthName = eIDrespInt.getEIDInfo(EIDKeys.BIRTH_NAME);
    EIDInfoResult familyNames = eIDrespInt.getEIDInfo(EIDKeys.FAMILY_NAMES);
    String familyNamesStr = familyNames instanceof EIDInfoResultString
      ? ((EIDInfoResultString)familyNames).getResult() : "";
    EIDInfoResult givenNames = eIDrespInt.getEIDInfo(EIDKeys.GIVEN_NAMES);
    String givenNamesStr = givenNames instanceof EIDInfoResultString
      ? ((EIDInfoResultString)givenNames).getResult() : "";

    // if birth name is requested, build it according to TR03130-3 section 3.2
    if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.BIRTH_NAME) != null)
    {
      // deselected or not on chip, do not add attribute...
      if (birthName instanceof EIDInfoResultDeselected || birthName instanceof EIDInfoResultNotOnChip)
      {
        // ... but send error if mandatory
        if (samlReqSession.getRequestedAttributes()
                          .get(EidasNaturalPersonAttributes.BIRTH_NAME)
                          .booleanValue())
        {
          return false;
        }
      }
      else
      {
        String constructedBirthName = givenNamesStr + " ";
        String birthNameStr = birthName instanceof EIDInfoResultString
          ? ((EIDInfoResultString)birthName).getResult() : "";
        if (StringUtil.notEmpty(birthNameStr))
        {
          constructedBirthName += birthNameStr;
        }
        else
        {
          constructedBirthName += familyNamesStr;
        }
        attributes.add(new BirthNameAttribute(constructedBirthName));
      }
    }

    if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.FAMILY_NAME) != null)

    {
      if (familyNames instanceof EIDInfoResultString)
      {
        attributes.add(new FamilyNameAttribute(familyNamesStr));
      }
      else if (samlReqSession.getRequestedAttributes()
                             .get(EidasNaturalPersonAttributes.FAMILY_NAME)
                             .booleanValue())
      {
        return false;
      }
    }

    if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.FIRST_NAME) != null)
    {
      if (givenNames instanceof EIDInfoResultString)
      {
        attributes.add(new GivenNameAttribute(givenNamesStr));
      }
      else if (samlReqSession.getRequestedAttributes()
                             .get(EidasNaturalPersonAttributes.FIRST_NAME)
                             .booleanValue())
      {
        return false;
      }
    }

    return true;
  }

  /**
   * Create a well defined address attribute.
   *
   * @param eIDrespInt The list with the eID responses
   * @param attributes The list with the eIDAS attributes
   */
  protected boolean createPlaceOfResidence(EIDResultResponse eIDrespInt,
                                           List<EidasAttribute> attributes,
                                           RequestSession samlReqSession)
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
    else if (samlReqSession.getRequestedAttributes().get(EidasNaturalPersonAttributes.CURRENT_ADDRESS) != null
             && samlReqSession.getRequestedAttributes()
                              .get(EidasNaturalPersonAttributes.CURRENT_ADDRESS)
                              .booleanValue())
    {
      return false;
    }
    return true;
  }

  /**
   * Separates the street from the number of an address, if number exists.
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

  public String getConsumerURLForRefID(String refID)
  {
    RequestSession samlReqSession = getSAMLReqSession(refID);
    if (samlReqSession == null)
    {
      throw new RequestProcessingException(UNKNOWN_REF_ID);
    }
    RequestingServiceProvider reqSP = serviceProviderConfig.getProviderByEntityID(samlReqSession.getReqProviderEntityId());
    return reqSP.getAssertionConsumerURL();
  }

  public String getRelayStateForRefID(String refID)
  {
    RequestSession samlReqSession = getSAMLReqSession(refID);
    if (samlReqSession == null)
    {
      throw new RequestProcessingException(UNKNOWN_REF_ID);
    }
    return samlReqSession.getRelayState().orElse(null);
  }
}
