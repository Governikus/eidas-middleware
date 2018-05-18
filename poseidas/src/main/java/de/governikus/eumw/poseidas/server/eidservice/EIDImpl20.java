/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.nio.charset.StandardCharsets;
import java.util.Map.Entry;

import javax.annotation.Resource;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.WebServiceContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.SAXParseException;

import com.sun.xml.ws.developer.SchemaValidation;

import de.bund.bsi.eid20.AttributeRequestType;
import de.bund.bsi.eid20.AttributeResponseType;
import de.bund.bsi.eid20.AttributeSelectionType;
import de.bund.bsi.eid20.EID;
import de.bund.bsi.eid20.GeneralDateType;
import de.bund.bsi.eid20.GeneralPlaceType;
import de.bund.bsi.eid20.GetResultRequestType;
import de.bund.bsi.eid20.GetResultResponseType;
import de.bund.bsi.eid20.GetServerInfoResponseType;
import de.bund.bsi.eid20.NullType;
import de.bund.bsi.eid20.ObjectFactory;
import de.bund.bsi.eid20.OperationsRequestorType;
import de.bund.bsi.eid20.OperationsResponderType;
import de.bund.bsi.eid20.OperationsSelectorType;
import de.bund.bsi.eid20.PersonalDataType;
import de.bund.bsi.eid20.PlaceType;
import de.bund.bsi.eid20.PreSharedKeyType;
import de.bund.bsi.eid20.RestrictedIDType;
import de.bund.bsi.eid20.SessionType;
import de.bund.bsi.eid20.UseIDRequestType;
import de.bund.bsi.eid20.UseIDResponseType;
import de.bund.bsi.eid20.VerificationResultType;
import de.bund.bsi.eid20.VersionType;
import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultByteArray;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultListByteArray;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultNotOnChip;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceFreeText;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceNo;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPlaceStructured;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultPseudonymousSignature;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultRestrictedID;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResultVerification;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.idprovider.core.AuthenticationSessionManager;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * eID web service implementation according to TR-03130 version 2.0.0. This code reads the 2.0.0 request and
 * converts it into a internal request to forward it to the functions in {@link EIDInternal} actually doing
 * something and the result will them be converted into a eID-Webservice response.
 * 
 * @author CM, TT
 * @author Hauke Mehrtens
 */
@WebService(name = "eID", portName = "eIDSOAP", serviceName = "eID", targetNamespace = "http://bsi.bund.de/eID/", wsdlLocation = "WEB-INF/wsdl/TR-03130eID-Server20.wsdl")
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
@SchemaValidation(handler = SchemaValidationHandler.class)
public class EIDImpl20 extends EIDImpl implements EID
{

  private static final Log LOG = LogFactory.getLog(EIDImpl20.class);

  private static final ObjectFactory FACTORY = new ObjectFactory();

  @Resource
  WebServiceContext context;

  @Override
  public GetResultResponseType getResult(GetResultRequestType parameters)
  {
    SAXParseException parseException = (SAXParseException)context.getMessageContext()
                                                                 .get(SchemaValidationHandler.XML_ERROR);
    if (parseException != null)
    {
      // even if the XML is corrupt, we shall believe the eventually contained session ID and end the session
      // (yes, it is specified this way!)
      if (parameters.getSession() != null && parameters.getSession().getID() != null)
      {
        String requestId = new String(parameters.getSession().getID(), StandardCharsets.UTF_8);
        EIDSession session = AuthenticationSessionManager.getInstance().getByRequestId(requestId,
                                                                                       EIDSession.class);
        AuthenticationSessionManager.getInstance().remove(session);
      }

      GetResultResponseType response = new GetResultResponseType();
      Result result = createSchemaViolationResult(parseException.getMessage());
      response.setResult(result);
      return response;
    }

    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    identifyClient(context, config);
    String requestId = null;
    if (parameters.getSession() != null && parameters.getSession().getID() != null)
    {
      requestId = new String(parameters.getSession().getID(), StandardCharsets.UTF_8);
    }

    EIDResultResponse eidResponse = EIDInternal.getInstance().getResult(requestId,
                                                                        parameters.getRequestCounter());

    if (LOG.isInfoEnabled())
    {
      LOG.info(eidResponse.getLogPrefix() + "getResult: eID-Response: "
               + resultToString(eidResponse.getResult()));
    }

    GetResultResponseType response = new GetResultResponseType();

    OperationsResponderType allowedByUser = FACTORY.createOperationsResponderType();
    response.setResult(eidResponse.getResult());

    if (!eidResponse.getInfoMap().isEmpty())
    {
      setNothingAllowedResponder(allowedByUser);
      response.setOperationsAllowedByUser(allowedByUser);
      PersonalDataType data = FACTORY.createPersonalDataType();
      response.setPersonalData(data);
      for ( Entry<EIDKeys, EIDInfoResult> entry : eidResponse.getInfoMap().entrySet() )
      {
        if (entry.getValue() instanceof EIDInfoResultNotOnChip)
        {
          setNotOnChip(entry.getKey(), allowedByUser, eidResponse.getLogPrefix());
        }
        else
        {
          setValue(entry.getKey(),
                   entry.getValue(),
                   data,
                   allowedByUser,
                   response,
                   eidResponse.getLogPrefix());
        }
      }
    }
    return response;
  }

  private static void setNothingAllowedResponder(OperationsResponderType allowedByUser)
  {
    allowedByUser.setAcademicTitle(AttributeResponseType.PROHIBITED);
    allowedByUser.setAgeVerification(AttributeResponseType.PROHIBITED);
    allowedByUser.setArtisticName(AttributeResponseType.PROHIBITED);
    allowedByUser.setBirthName(AttributeResponseType.PROHIBITED);
    allowedByUser.setDateOfBirth(AttributeResponseType.PROHIBITED);
    allowedByUser.setDateOfExpiry(AttributeResponseType.PROHIBITED);
    allowedByUser.setDateOfIssuance(AttributeResponseType.PROHIBITED);
    allowedByUser.setDocumentType(AttributeResponseType.PROHIBITED);
    allowedByUser.setEmailAddress(AttributeResponseType.PROHIBITED);
    allowedByUser.setFamilyNames(AttributeResponseType.PROHIBITED);
    allowedByUser.setGivenNames(AttributeResponseType.PROHIBITED);
    allowedByUser.setIssuingState(AttributeResponseType.PROHIBITED);
    allowedByUser.setMunicipalityID(AttributeResponseType.PROHIBITED);
    allowedByUser.setNationality(AttributeResponseType.PROHIBITED);
    allowedByUser.setOptionalDataR(AttributeResponseType.PROHIBITED);
    allowedByUser.setPhoneNumber(AttributeResponseType.PROHIBITED);
    allowedByUser.setPlaceOfBirth(AttributeResponseType.PROHIBITED);
    allowedByUser.setPlaceOfResidence(AttributeResponseType.PROHIBITED);
    allowedByUser.setPlaceVerification(AttributeResponseType.PROHIBITED);
    allowedByUser.setPSA(AttributeResponseType.PROHIBITED);
    allowedByUser.setPSC(AttributeResponseType.PROHIBITED);
    allowedByUser.setPSM(AttributeResponseType.PROHIBITED);
    allowedByUser.setRestrictedID(AttributeResponseType.PROHIBITED);
    allowedByUser.setResidencePermitI(AttributeResponseType.PROHIBITED);
    allowedByUser.setResidencePermitII(AttributeResponseType.PROHIBITED);
    allowedByUser.setSex(AttributeResponseType.PROHIBITED);
    allowedByUser.setWrittenSignature(AttributeResponseType.PROHIBITED);
    allowedByUser.setSpecificAttribute(AttributeResponseType.PROHIBITED);
  }

  private static void setValue(EIDKeys key,
                               EIDInfoResult value,
                               PersonalDataType data,
                               OperationsResponderType allowedByUser,
                               GetResultResponseType response,
                               String logPrefix)
  {
    EIDInfoResultVerification eidInfoVerify;
    switch (key)
    {
      case DOCUMENT_TYPE:
        data.setDocumentType(value.toString());
        allowedByUser.setDocumentType(AttributeResponseType.ALLOWED);
        break;
      case ISSUING_STATE:
        data.setIssuingState(value.toString());
        allowedByUser.setIssuingState(AttributeResponseType.ALLOWED);
        break;
      case DATE_OF_EXPIRY:
        data.setDateOfExpiry(createXMLDate(value.toString(), logPrefix));
        allowedByUser.setDateOfExpiry(AttributeResponseType.ALLOWED);
        break;
      case GIVEN_NAMES:
        data.setGivenNames(value.toString());
        allowedByUser.setGivenNames(AttributeResponseType.ALLOWED);
        break;
      case FAMILY_NAMES:
        data.setFamilyNames(value.toString());
        allowedByUser.setFamilyNames(AttributeResponseType.ALLOWED);
        break;
      case NOM_DE_PLUME:
        data.setArtisticName(value.toString());
        allowedByUser.setArtisticName(AttributeResponseType.ALLOWED);
        break;
      case ACADEMIC_TITLE:
        data.setAcademicTitle(value.toString());
        allowedByUser.setAcademicTitle(AttributeResponseType.ALLOWED);
        break;
      case DATE_OF_BIRTH:
        data.setDateOfBirth(createDate(value.toString(), logPrefix));
        allowedByUser.setDateOfBirth(AttributeResponseType.ALLOWED);
        break;
      case PLACE_OF_BIRTH:
        data.setPlaceOfBirth(createPlace(value));
        allowedByUser.setPlaceOfBirth(AttributeResponseType.ALLOWED);
        break;
      case NATIONALITY:
        data.setNationality(value.toString());
        allowedByUser.setNationality(AttributeResponseType.ALLOWED);
        break;
      case SEX: // not supported by eID interface!
        data.setSex(value.toString());
        allowedByUser.setSex(AttributeResponseType.ALLOWED);
        break;
      case OPTIONAL_DATA_R: // not supported by eID interface!
        data.setOptionalDataR(((EIDInfoResultByteArray)value).getResult());
        allowedByUser.setOptionalDataR(AttributeResponseType.ALLOWED);
        break;
      case BIRTH_NAME:// new in 2.0
        data.setBirthName(value.toString());
        allowedByUser.setBirthName(AttributeResponseType.ALLOWED);
        break;
      case WRITTEN_SIGNATURE: // not supported by eID interface!
        data.setWrittenSignature(((EIDInfoResultByteArray)value).getResult());
        allowedByUser.setWrittenSignature(AttributeResponseType.ALLOWED);
        break;
      case DATE_OF_ISSUANCE: // not supported by eID interface!
        data.setDateOfIssuance(createXMLDate(value.toString(), logPrefix));
        allowedByUser.setDateOfIssuance(AttributeResponseType.ALLOWED);
        break;
      case PLACE_OF_RESIDENCE:
        data.setPlaceOfResidence(createPlace(value));
        allowedByUser.setPlaceOfResidence(AttributeResponseType.ALLOWED);
        break;
      case MUNICIPALITY_ID: // not supported by eID interface!
        data.setMunicipalityID(((EIDInfoResultByteArray)value).getResult());
        allowedByUser.setMunicipalityID(AttributeResponseType.ALLOWED);
        break;
      case RESIDENCE_PERMIT_I:
        data.setResidencePermitI(value.toString());
        allowedByUser.setResidencePermitI(AttributeResponseType.ALLOWED);
        break;
      case RESIDENCE_PERMIT_II:
        data.setResidencePermitII(value.toString());
        allowedByUser.setResidencePermitII(AttributeResponseType.ALLOWED);
        break;
      case PHONE_NUMBER: // not supported by eID interface!
        data.setPhoneNumber(value.toString());
        allowedByUser.setPhoneNumber(AttributeResponseType.ALLOWED);
        break;
      case EMAIL_ADDRESS: // not supported by eID interface!
        data.setEmailAddress(value.toString());
        allowedByUser.setEmailAddress(AttributeResponseType.ALLOWED);
        break;
      case RESTRICTED_ID:
        EIDInfoResultRestrictedID eidInfoRest = (EIDInfoResultRestrictedID)value;
        RestrictedIDType id = new RestrictedIDType();
        id.setID(eidInfoRest.getID1());
        id.setID2(eidInfoRest.getID2());
        data.setRestrictedID(id);
        allowedByUser.setRestrictedID(AttributeResponseType.ALLOWED);
        break;
      case AGE_VERIFICATION:
        eidInfoVerify = (EIDInfoResultVerification)value;
        VerificationResultType verResult = new VerificationResultType();
        verResult.setFulfilsRequest(eidInfoVerify.isVertificationResult());
        response.setFulfilsAgeVerification(verResult);
        allowedByUser.setAgeVerification(AttributeResponseType.ALLOWED);
        break;
      case MUNICIPALITY_ID_VERIFICATION:
        eidInfoVerify = (EIDInfoResultVerification)value;
        verResult = new VerificationResultType();
        verResult.setFulfilsRequest(eidInfoVerify.isVertificationResult());
        response.setFulfilsPlaceVerification(verResult);
        allowedByUser.setPlaceVerification(AttributeResponseType.ALLOWED);
        break;
      case PSA:
        response.setPSA(((EIDInfoResultPseudonymousSignature)value).getSignature());
        Boolean verified = ((EIDInfoResultPseudonymousSignature)value).getVerified();
        if (verified != null)
        {
          verResult = new VerificationResultType();
          verResult.setFulfilsRequest(verified);
          response.setPSAVerified(verResult);
        }
        allowedByUser.setPSA(AttributeResponseType.ALLOWED);
        break;
      case PSM:
        response.setPSM(((EIDInfoResultPseudonymousSignature)value).getSignature());
        verified = ((EIDInfoResultPseudonymousSignature)value).getVerified();
        if (verified != null)
        {
          verResult = new VerificationResultType();
          verResult.setFulfilsRequest(verified);
          response.setPSMVerified(verResult);
        }
        allowedByUser.setPSM(AttributeResponseType.ALLOWED);
        break;
      case PSC:
        response.setPSC(((EIDInfoResultPseudonymousSignature)value).getSignature());
        allowedByUser.setPSC(AttributeResponseType.ALLOWED);
        break;
      case SPECIFIC_ATTRIBUTES:
        response.getSpecificAttribute().addAll(((EIDInfoResultListByteArray)value).getResult());
        allowedByUser.setSpecificAttribute(AttributeResponseType.ALLOWED);
        break;
      case DOCUMENT_VALIDITY:
        // this is handled by an error code
        break;
      case INSTALL_QUALIFIED_CERTIFICATE:
        LOG.warn(logPrefix + key + " not supported by eID-Webservice 2.0");
        break;
      case DELETE_SPECIFIC_ATTRIBUTES:
      case PROVIDE_GLOBAL_GENERIC_ATTRIBUTES:
      case PROVIDE_SPECIFIC_ATTRIBUTES:
        break;
    }
  }

  private static void setNotOnChip(EIDKeys key, OperationsResponderType allowedByUser, String logPrefix)
  {
    switch (key)
    {
      case DOCUMENT_TYPE:
        allowedByUser.setDocumentType(AttributeResponseType.NOTONCHIP);
        break;
      case ISSUING_STATE:
        allowedByUser.setIssuingState(AttributeResponseType.NOTONCHIP);
        break;
      case DATE_OF_EXPIRY: // new in 2.0
        allowedByUser.setDateOfExpiry(AttributeResponseType.NOTONCHIP);
        break;
      case GIVEN_NAMES:
        allowedByUser.setGivenNames(AttributeResponseType.NOTONCHIP);
        break;
      case FAMILY_NAMES:
        allowedByUser.setFamilyNames(AttributeResponseType.NOTONCHIP);
        break;
      case NOM_DE_PLUME:
        allowedByUser.setArtisticName(AttributeResponseType.NOTONCHIP);
        break;
      case ACADEMIC_TITLE:
        allowedByUser.setAcademicTitle(AttributeResponseType.NOTONCHIP);
        break;
      case DATE_OF_BIRTH:
        allowedByUser.setDateOfBirth(AttributeResponseType.NOTONCHIP);
        break;
      case PLACE_OF_BIRTH:
        allowedByUser.setPlaceOfBirth(AttributeResponseType.NOTONCHIP);
        break;
      case NATIONALITY:
        allowedByUser.setNationality(AttributeResponseType.NOTONCHIP);
        break;
      case SEX: // not supported by eID interface!
        allowedByUser.setSex(AttributeResponseType.NOTONCHIP);
        break;
      case OPTIONAL_DATA_R: // not supported by eID interface!
        allowedByUser.setOptionalDataR(AttributeResponseType.NOTONCHIP);
        break;
      case BIRTH_NAME:// new in 2.0
        allowedByUser.setBirthName(AttributeResponseType.NOTONCHIP);
        break;
      case WRITTEN_SIGNATURE: // not supported by eID interface!
        allowedByUser.setWrittenSignature(AttributeResponseType.NOTONCHIP);
        break;
      case DATE_OF_ISSUANCE: // not supported by eID interface!
        allowedByUser.setDateOfIssuance(AttributeResponseType.NOTONCHIP);
        break;
      case PLACE_OF_RESIDENCE:
        allowedByUser.setPlaceOfResidence(AttributeResponseType.NOTONCHIP);
        break;
      case MUNICIPALITY_ID: // not supported by eID interface!
        allowedByUser.setMunicipalityID(AttributeResponseType.NOTONCHIP);
        break;
      case RESIDENCE_PERMIT_I:
        allowedByUser.setResidencePermitI(AttributeResponseType.NOTONCHIP);
        break;
      case RESIDENCE_PERMIT_II:
        allowedByUser.setResidencePermitII(AttributeResponseType.NOTONCHIP);
        break;
      case PHONE_NUMBER:
        allowedByUser.setPhoneNumber(AttributeResponseType.NOTONCHIP);
        break;
      case EMAIL_ADDRESS:
        allowedByUser.setEmailAddress(AttributeResponseType.NOTONCHIP);
        break;
      case RESTRICTED_ID:
        allowedByUser.setRestrictedID(AttributeResponseType.NOTONCHIP);
        break;
      case AGE_VERIFICATION:
        allowedByUser.setAgeVerification(AttributeResponseType.NOTONCHIP);
        break;
      case MUNICIPALITY_ID_VERIFICATION:
        allowedByUser.setPlaceVerification(AttributeResponseType.NOTONCHIP);
        break;
      case PSA:
        allowedByUser.setPSA(AttributeResponseType.NOTONCHIP);
        break;
      case PSM:
        allowedByUser.setPSM(AttributeResponseType.NOTONCHIP);
        break;
      case PSC:
        allowedByUser.setPSC(AttributeResponseType.NOTONCHIP);
        break;
      case DOCUMENT_VALIDITY:
        // this is handled by an error code
        break;
      case INSTALL_QUALIFIED_CERTIFICATE:
        LOG.warn(logPrefix + key + " not supported by eID-Webservice 2.0");
        break;
      case DELETE_SPECIFIC_ATTRIBUTES:
      case PROVIDE_GLOBAL_GENERIC_ATTRIBUTES:
      case PROVIDE_SPECIFIC_ATTRIBUTES:
      case SPECIFIC_ATTRIBUTES:
    }
  }

  /**
   * Transform a date string coming from applet to XML compatible format
   * 
   * @param input expected in format YYYYMMDD
   * @param logPrefix
   * @return date in XML representation
   */
  private static GeneralDateType createDate(String input, String logPrefix)
  {
    if (input == null)
    {
      return null;
    }
    GeneralDateType result = new GeneralDateType();
    result.setDateString(input);
    if (input.trim().length() == 8)
    {
      XMLGregorianCalendar xmlDate = createXMLDate(input, logPrefix);
      if (xmlDate != null)
      {
        result.setDateValue(xmlDate);
      }
    }
    return result;
  }

  /**
   * Create a Place object.
   * 
   * @param value <State>;<Country>;<PLZ>;<City>;<Street>
   * @return place in XML representation
   */
  private static GeneralPlaceType createPlace(EIDInfoResult value)
  {
    GeneralPlaceType result = new GeneralPlaceType();
    if (value instanceof EIDInfoResultPlaceStructured)
    {
      EIDInfoResultPlaceStructured info = (EIDInfoResultPlaceStructured)value;
      PlaceType place = new PlaceType();
      place.setCountry(info.getCountry());
      place.setState(info.getState());
      place.setZipCode(info.getZipCode());
      place.setCity(info.getCity());
      place.setStreet(info.getStreet());
      result.setStructuredPlace(place);
    }
    else if (value instanceof EIDInfoResultPlaceFreeText)
    {
      EIDInfoResultPlaceFreeText info = (EIDInfoResultPlaceFreeText)value;
      result.setFreetextPlace(info.getFreeTextPlace());
    }
    else if (value instanceof EIDInfoResultPlaceNo)
    {
      EIDInfoResultPlaceNo info = (EIDInfoResultPlaceNo)value;
      result.setNoPlaceInfo(info.getNoPlaceInfo());
    }
    return result;
  }

  @Override
  public GetServerInfoResponseType getServerInfo(NullType parameters)
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto prov = identifyClient(context, config);
    GetServerInfoResponseType response = new GetServerInfoResponseType();
    VersionType version = new VersionType();
    version.setMajor(2);
    version.setMinor(0);
    version.setBugfix(Integer.valueOf(0));
    version.setVersionString("Poseidas 1.0.x (eID-Webservice 2.0)");
    response.setServerVersion(version);
    fillDocumentVerificationRights(response, prov);
    return response;
  }

  private void fillDocumentVerificationRights(GetServerInfoResponseType response, ServiceProviderDto provider)
  {
    OperationsSelectorType selector = new OperationsSelectorType();
    response.setDocumentVerificationRights(selector);
    TerminalData cvc = getCVC(provider.getEpaConnectorConfiguration().getCVCRefID());
    if (cvc != null)
    {
      CertificateHolderAuthorizationTemplate chat = cvc.getCHAT();

      selector.setAcademicTitle(getType(chat.isReadAcademicTitle()));
      selector.setAgeVerification(getType(chat.isAuthenticateAgeVerification()));
      selector.setArtisticName(getType(chat.isReadNomDePlume()));
      selector.setBirthName(getType(chat.isReadBirthName()));// new in 2.0
      selector.setDateOfBirth(getType(chat.isReadDateOfBirth()));
      selector.setDateOfExpiry(getType(chat.isReadDateOfExpiry()));// new in 2.0
      selector.setDateOfIssuance(getType(chat.isReadDateOfIssuance()));
      selector.setDocumentType(getType(chat.isReadDocumentType()));
      selector.setFamilyNames(getType(chat.isReadFamilyNames()));
      selector.setGivenNames(getType(chat.isReadGivenNames()));
      selector.setIssuingState(getType(chat.isReadIssuingState()));
      selector.setNationality(getType(chat.isReadNationality()));
      selector.setPlaceOfBirth(getType(chat.isReadPlaceOfBirth()));
      selector.setPlaceOfResidence(getType(chat.isReadPlaceOfResidence()));
      selector.setPlaceVerification(getType(chat.isAuthenticateMunicipalityIDVerification()));
      selector.setRestrictedID(getType(chat.isAuthenticateRestrictedIdentification()));
      selector.setResidencePermitI(getType(chat.isReadResidencePermitI()));
      return;
    }

    selector.setAcademicTitle(AttributeSelectionType.ALLOWED);
    selector.setAgeVerification(AttributeSelectionType.ALLOWED);
    selector.setArtisticName(AttributeSelectionType.ALLOWED);
    selector.setBirthName(AttributeSelectionType.ALLOWED);// new in 2.0
    selector.setDateOfBirth(AttributeSelectionType.ALLOWED);
    selector.setDateOfExpiry(AttributeSelectionType.ALLOWED); // new in 2.0
    selector.setDateOfIssuance(AttributeSelectionType.ALLOWED); // new in 2.0
    selector.setDocumentType(AttributeSelectionType.ALLOWED);
    selector.setFamilyNames(AttributeSelectionType.ALLOWED);
    selector.setGivenNames(AttributeSelectionType.ALLOWED);
    selector.setIssuingState(AttributeSelectionType.ALLOWED);
    selector.setNationality(AttributeSelectionType.ALLOWED);
    selector.setPlaceOfBirth(AttributeSelectionType.ALLOWED);
    selector.setPlaceOfResidence(AttributeSelectionType.ALLOWED);
    selector.setPlaceVerification(AttributeSelectionType.ALLOWED);
    selector.setRestrictedID(AttributeSelectionType.ALLOWED);
    selector.setResidencePermitI(AttributeSelectionType.ALLOWED);
  }

  private AttributeSelectionType getType(boolean allowed)
  {
    return allowed ? AttributeSelectionType.ALLOWED : AttributeSelectionType.PROHIBITED;
  }

  @Override
  public UseIDResponseType useID(UseIDRequestType parameters)
  {
    SAXParseException parseException = (SAXParseException)context.getMessageContext()
                                                                 .get(SchemaValidationHandler.XML_ERROR);
    if (parseException != null)
    {
      UseIDResponseType response = new UseIDResponseType();
      Result result = createSchemaViolationResult(parseException.getMessage());
      response.setResult(result);
      return response;
    }

    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto prov = identifyClient(context, config);

    EIDRequestInput request = new EIDRequestInput(false, true);
    request.setConfig(config);
    if (parameters.getPSK() != null)
    {
      request.setPsk(parameters.getPSK().getKey());
      request.setSessionId(parameters.getPSK().getID());
    }
    if (parameters.getAgeVerificationRequest() != null)
    {
      request.setRequestedMinAge(parameters.getAgeVerificationRequest().getAge());
    }
    if (parameters.getPlaceVerificationRequest() != null)
    {
      request.setRequestedCommunityIDPattern(parameters.getPlaceVerificationRequest().getCommunityID());
    }
    request.setMessagePSM(parameters.getPSMRequest());
    request.setParametersPSC(parameters.getPSCRequest());
    request.setParametersSART(parameters.getSpecificAttributeRequest());
    if (refId.get() != null)
    {
      request.setRequestId(refId.get());
    }
    OperationsRequestorType useOperations = parameters.getUseOperations();

    addAttribte(request, useOperations.getDocumentType(), EIDKeys.DOCUMENT_TYPE);
    addAttribte(request, useOperations.getIssuingState(), EIDKeys.ISSUING_STATE);
    addAttribte(request, useOperations.getDateOfExpiry(), EIDKeys.DATE_OF_EXPIRY);
    addAttribte(request, useOperations.getGivenNames(), EIDKeys.GIVEN_NAMES);
    addAttribte(request, useOperations.getFamilyNames(), EIDKeys.FAMILY_NAMES);
    addAttribte(request, useOperations.getArtisticName(), EIDKeys.NOM_DE_PLUME);
    addAttribte(request, useOperations.getAcademicTitle(), EIDKeys.ACADEMIC_TITLE);
    addAttribte(request, useOperations.getDateOfBirth(), EIDKeys.DATE_OF_BIRTH);
    addAttribte(request, useOperations.getPlaceOfBirth(), EIDKeys.PLACE_OF_BIRTH);
    addAttribte(request, useOperations.getNationality(), EIDKeys.NATIONALITY);
    addAttribte(request, useOperations.getSex(), EIDKeys.SEX);
    addAttribte(request, useOperations.getOptionalDataR(), EIDKeys.OPTIONAL_DATA_R);
    addAttribte(request, useOperations.getBirthName(), EIDKeys.BIRTH_NAME);
    addAttribte(request, useOperations.getWrittenSignature(), EIDKeys.WRITTEN_SIGNATURE);
    addAttribte(request, useOperations.getDateOfIssuance(), EIDKeys.DATE_OF_ISSUANCE);
    addAttribte(request, useOperations.getPlaceOfResidence(), EIDKeys.PLACE_OF_RESIDENCE);
    addAttribte(request, useOperations.getMunicipalityID(), EIDKeys.MUNICIPALITY_ID);
    addAttribte(request, useOperations.getResidencePermitI(), EIDKeys.RESIDENCE_PERMIT_I);
    addAttribte(request, useOperations.getResidencePermitII(), EIDKeys.RESIDENCE_PERMIT_II);
    addAttribte(request, useOperations.getPhoneNumber(), EIDKeys.PHONE_NUMBER);
    addAttribte(request, useOperations.getEmailAddress(), EIDKeys.EMAIL_ADDRESS);
    addAttribte(request, useOperations.getRestrictedID(), EIDKeys.RESTRICTED_ID);
    addAttribte(request, useOperations.getAgeVerification(), EIDKeys.AGE_VERIFICATION);
    addAttribte(request, useOperations.getPlaceVerification(), EIDKeys.MUNICIPALITY_ID_VERIFICATION);
    addAttribte(request, useOperations.getPSC(), EIDKeys.PSC);
    addAttribte(request, useOperations.getPSM(), EIDKeys.PSM);
    addAttribte(request, useOperations.getPSA(), EIDKeys.PSA);
    addAttribte(request, useOperations.getSpecificAttribute(), EIDKeys.SPECIFIC_ATTRIBUTES);
    addAttribte(request, useOperations.getDeleteSpecificAttribute(), EIDKeys.DELETE_SPECIFIC_ATTRIBUTES);

    EIDRequestResponse eidResult = EIDInternal.getInstance().useID(request, prov);

    if (LOG.isInfoEnabled())
    {
      LOG.info(eidResult.getLogPrefix() + "useID: eID-Response: " + resultToString(eidResult.getResult()));
    }

    UseIDResponseType response = new UseIDResponseType();
    response.setResult(eidResult.getResult());

    PreSharedKeyType psk = new PreSharedKeyType();
    psk.setKey(eidResult.getPsk());
    psk.setID(eidResult.getSessionId());
    response.setPSK(psk);

    SessionType session = new SessionType();
    session.setID(eidResult.getRequestId().getBytes(StandardCharsets.UTF_8));
    response.setSession(session);

    if (Constants.EID_MAJOR_OK.equals(eidResult.getResultMajor()))
    {
      response.setECardServerAddress(eidResult.getECardServerAddress());
    }

    return response;
  }

  private void addAttribte(EIDRequestInput request, AttributeRequestType requestType, EIDKeys key)
  {
    if (AttributeRequestType.REQUIRED == requestType)
    {
      request.addRequiredFields(key);
    }
    if (AttributeRequestType.ALLOWED == requestType)
    {
      request.addOptionalFields(key);
    }
  }

  private static Result createSchemaViolationResult(String message)
  {
    Result r = new Result();
    r.setResultMajor(Constants.EID_MAJOR_ERROR);
    r.setResultMinor(Constants.EID_MINOR_COMMON_SCHEMA_VIOLATION);
    r.setResultMessage(ECardCoreUtil.generateInternationalStringType(message));
    return r;
  }
}
