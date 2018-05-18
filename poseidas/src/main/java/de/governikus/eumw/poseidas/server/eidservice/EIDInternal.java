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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.bund.bsi.eid20.PSCRequestType;
import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccess;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributes;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDSequence.Authorizations;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerFactory;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerI;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.idprovider.core.AuthenticationSessionManager;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Functional implementation of the eID-interface. This class provides an API which can be used from inside
 * the server instead of the WebService interface.
 * 
 * @author CM, TT
 * @author hauke
 */

public final class EIDInternal
{

  private static final Log LOG = LogFactory.getLog(EIDInternal.class);

  private final SecureRandom pskSource = new SecureRandom();

  private static EIDInternal instance = new EIDInternal();

  private boolean initDone = false;

  public synchronized void init()
  {
    if (initDone)
    {
      return;
    }
    ECardIDServerI server = ECardIDServerFactory.getInstance().getCurrentServer();
    server.setECardIDCallbackListener(EIDSessionCallbackHandler.getInstance());
    initDone = true;
  }

  /**
   * for getting the single instance of EIDInternal
   * 
   * @return single instance of EIDInternal
   */
  public static EIDInternal getInstance()
  {
    return instance;
  }

  private final AuthenticationSessionManager sessionManager = AuthenticationSessionManager.getInstance();

  /**
   * Perform a useID-Request as described in the WSDL.
   * 
   * @param request describes the requested data
   * @param client identifies the provider by used SSL client certificate
   * @return {@link EIDRequestResponse} contains session id and pre-shared key
   */
  public EIDRequestResponse useID(EIDRequestInput request, ServiceProviderDto client)
  {
    if (client != null)
    {
      LOG.debug("identified client " + client.getEntityID());
    }
    else
    {
      LOG.error("called useID() without client");
    }
    CoreConfigurationDto cconf = request.getConfig();
    if (cconf == null)
    {
      cconf = PoseidasConfigurator.getInstance().getCurrentConfig();
    }
    String requestId = request.getRequestId();
    if (requestId == null || requestId.trim().isEmpty())
    {
      requestId = Utils.generateUniqueID();
    }
    String sessionId = requestId;
    if (request.isSessionIdMayDiffer())
    {
      sessionId = request.getSessionId();
      if (sessionId == null || sessionId.trim().isEmpty())
      {
        sessionId = Utils.generateUniqueID();
      }
    }
    byte[] preSharedKey = null;
    if (request.getPsk() == null)
    {
      preSharedKey = new byte[64];
      pskSource.nextBytes(preSharedKey);
    }
    else
    {
      preSharedKey = request.getPsk();
    }
    EIDRequestResponse errorResponse = checkRequestError(request, sessionId, requestId, preSharedKey, client);
    if (errorResponse != null)
    {
      return errorResponse;
    }
    EPAConnectorConfigurationDto config = client.getEpaConnectorConfiguration();
    boolean demoEnabled = config.getPaosReceiverURL().endsWith("epa_dummy");
    EIDSession mySession = new EIDSession(sessionId, requestId, request.isSaml(), demoEnabled,
                                          client.getEntityID());
    EIDRequestResponse response = new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_OK, null,
                                                         null, preSharedKey, config.getPaosReceiverURL(),
                                                         mySession.getLogPrefix());

    try
    {
      byte[] requestHash = request.getSamlHash();
      StringBuilder idProviderUrl = new StringBuilder(cconf.getServerUrl());
      idProviderUrl.append("/gov_autent/async");
      if (mySession.getRequestId() != null)
      {
        idProviderUrl.append('?');
        idProviderUrl.append(HttpRedirectUtils.REFERENCE_PARAMNAME);
        idProviderUrl.append('=');
        idProviderUrl.append(URLEncoder.encode(mySession.getRequestId(), Utils.ENCODING));
      }

      SessionInput input = null;

      if (demoEnabled)
      {
        input = new SessionInputImpl(null, null, preSharedKey, sessionId, requestHash, null,
                                     idProviderUrl.toString(), config.getCommunicationErrorURL(),
                                     config.getPaosReceiverURL(), (byte[])null, null, null,
                                     mySession.getLogPrefix());
      }
      else
      {
        input = startEcardApiRequest(mySession,
                                     preSharedKey,
                                     request,
                                     config.getCVCRefID(),
                                     requestHash,
                                     idProviderUrl.toString(),
                                     config.getCommunicationErrorURL(),
                                     config.getPaosReceiverURL());
        ECardIDServerFactory.getInstance().getCurrentServer();
      }
      mySession.setSessionInput(input);

      sessionManager.store(mySession);
    }
    catch (ErrorCodeException e)
    {
      String minorCode;
      switch (e.getCode())
      {
        case TOO_MANY_OPEN_SESSIONS:
          minorCode = Constants.EID_MINOR_USEID_TOO_MANY_OPEN_SESSIONS;
          break;
        case EID_MISSING_TERMINAL_RIGHTS:
          minorCode = Constants.EID_MINOR_USEID_MISSING_TERMINAL_RIGHTS;
          break;
        case EID_MISSING_ARGUMENT:
          minorCode = Constants.EID_MINOR_USEID_MISSING_ARGUMENT;
          break;
        default:
          minorCode = Constants.EID_MINOR_COMMON_INTERNALERROR;
          break;
      }
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR, minorCode,
                                    e.getMessage(), null, null, mySession.getLogPrefix());
    }
    catch (IllegalArgumentException e)
    {
      LOG.info(mySession.getLogPrefix() + "an internal error occurred while processing a request", e);
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR, e.getMessage(), null, null,
                                    mySession.getLogPrefix());
    }
    catch (UnsupportedEncodingException e)
    {
      LOG.info(mySession.getLogPrefix() + "an unsupported encoding was used", e);
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR, e.getMessage(), null, null,
                                    mySession.getLogPrefix());
    }
    return response;
  }

  private EIDRequestResponse checkRequestError(EIDRequestInput request,
                                               String sessionId,
                                               String requestId,
                                               byte[] preSharedKey,
                                               ServiceProviderDto client)
  {
    if (client == null)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR,
                                    "SSL certificate of client is unknown in the configuration", preSharedKey,
                                    null, "<unknown>: " + requestId + ": ");
    }
    else if (preSharedKey == null || preSharedKey.length < 16 || preSharedKey.length > 10240)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_INVALID_PSK,
                                    "The psk is too short with " + ((preSharedKey == null) ? 0
                                      : preSharedKey.length) + " bytes",
                                    preSharedKey, null, client.getEntityID() + ": " + requestId + ": ");
    }
    else if (sessionId == null || sessionId.length() < 16 || sessionId.length() > 10240)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "The session Id it too short with " + ((sessionId == null) ? 0
                                      : sessionId.length()) + " bytes",
                                    preSharedKey, null, client.getEntityID() + ": " + requestId + ": ");
    }
    else if (requestId == null || requestId.length() < 16 || requestId.length() > 10240)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "The Request ID it too short with " + ((requestId == null) ? 0
                                      : requestId.length()) + " bytes",
                                    preSharedKey, null, client.getEntityID() + ": " + requestId + ": ");
    }
    else if (ageVerificationRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify required age to perform age verification", preSharedKey,
                                    null, client.getEntityID() + ": " + requestId + ": ");
    }
    else if (placeVerificationRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify communityId to check against", preSharedKey, null,
                                    client.getEntityID() + ": " + requestId + ": ");
    }
    else if (psmRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify message to sign with PSM", preSharedKey, null,
                                    client.getEntityID() + ": " + requestId + ": ");
    }
    else if (pscRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify credentials to sign with PSC", preSharedKey, null,
                                    client.getEntityID() + ": " + requestId + ": ");
    }
    else if (specificAttributeRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must provide specific attribute request", preSharedKey, null,
                                    client.getEntityID() + ": " + requestId + ": ");
    }
    return null;
  }

  /**
   * @param refId
   * @return data Object containing all needed values except blacklist
   * @throws IllegalArgumentException
   */
  TerminalPermission getCVCData(String refId)
  {
      return cvcFacade.getTerminalPermission(refId);
  }


  private SessionInput startEcardApiRequest(EIDSession session,
                                            byte[] preSharedKey,
                                            EIDRequestInput request,
                                            String refId,
                                            byte[] sHA256ofSAMLRequest,
                                            String refreshAddress,
                                            String commErrorAddress,
                                            String serverAddress)
    throws ErrorCodeException
  {
    SessionInputImpl input;
    TerminalPermission tp = cvcFacade.getTerminalPermission(refId);
    if (tp == null)
    {
      throw new IllegalArgumentException("no cvc configured");
    }

    byte[] defectListData = tp.getDefectList();
    if (defectListData == null)
    {
      throw new IllegalArgumentException("no defect list stored");
    }

    byte[] masterListData = tp.getMasterList();
    if (masterListData == null)
    {
      throw new IllegalArgumentException("no master list stored");
    }
    TerminalData cvc = tp.getFullCvc();
    if (masterListData.length >= 2 && isZipData(masterListData))
    {
      List<X509Certificate> masterListCerts = addMasterListCertsFromZip(masterListData,
                                                                        session.getLogPrefix());
      input = new SessionInputImpl(cvc, tp.getCvcChain(), preSharedKey, session.getSessionId(),
                                   sHA256ofSAMLRequest,
                                   new BlackListConnectorImpl(cvcFacade, tp.getSectorID()), refreshAddress,
                                   commErrorAddress, serverAddress, masterListCerts, defectListData,
                                   request.getTransactionInfo(), session.getLogPrefix());
    }
    else
    {
      input = new SessionInputImpl(cvc, tp.getCvcChain(), preSharedKey, session.getSessionId(),
                                   sHA256ofSAMLRequest,
                                   new BlackListConnectorImpl(cvcFacade, tp.getSectorID()), refreshAddress,
                                   commErrorAddress, serverAddress, masterListData, defectListData,
                                   request.getTransactionInfo(), session.getLogPrefix());
    }
    translateSelector(request, input, cvc.getAuthorizations(), session.getLogPrefix());

    return input;
  }

  private boolean isZipData(byte[] data)
  {
    return data[0] == 0x50 && data[1] == 0X4b;
  }

  private List<X509Certificate> addMasterListCertsFromZip(byte[] listData, String logPrefix)
  {
    CertificateFactory certFactory;
    try
    {
      try
      {
        certFactory = CertificateFactory.getInstance("X509", BouncyCastleProvider.PROVIDER_NAME);
      }
      catch (NoSuchProviderException e)
      {
        certFactory = CertificateFactory.getInstance("X509");
      }
    }
    catch (CertificateException e)
    {
      // without certificate factory the is little we can do
      return null;
    }

    List<X509Certificate> result = new ArrayList<>();
    try
    {
      ZipInputStream ins = new ZipInputStream(new ByteArrayInputStream(listData));
      while (ins.getNextEntry() != null)
      {
        try
        {
          X509Certificate cert = (X509Certificate)certFactory.generateCertificate(ins);
          if (cert != null)
          {
            result.add(cert);
          }
        }
        catch (CertificateException e)
        {
          LOG.info(logPrefix + "Can not read a certificate from the master list zip file.", e);
        }
      }
      return result;
    }
    catch (IOException e)
    {
      LOG.error(logPrefix + "fake masterlist not readable", e);
    }
    return null;
  }

  private void translateSelector(EIDRequestInput request,
                                 SessionInputImpl input,
                                 Authorizations auth,
                                 String logPrefix)
    throws ErrorCodeException
  {
    for ( EIDKeys key : request.getRequiredFields() )
    {
      if (!isInAuth(key, auth))
      {
        throw new ErrorCodeException(ErrorCode.EID_MISSING_TERMINAL_RIGHTS, key.toString());
      }
      if (key == EIDKeys.AGE_VERIFICATION)
      {
        if (request.getRequestedMinAge() == 0)
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_ARGUMENT, "RequestedMinAge");
        }
        input.setAgeVerification(request.getRequestedMinAge(), true);
      }
      else if (key == EIDKeys.MUNICIPALITY_ID_VERIFICATION)
      {
        if (request.getRequestedCommunityIDPattern() == null)
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_ARGUMENT, "CommunityIDPattern");
        }
        input.setCommunityIDVerification(request.getRequestedCommunityIDPattern(), true);
      }
      else if (key == EIDKeys.PSM)
      {
        input.setPSM(request.getMessagePSM(), true);
      }
      else if (key == EIDKeys.PSC)
      {
        input.setPSC(request.getParametersPSC(), true);
        if (!this.checkFieldsForSignature(request.getParametersPSC(), auth))
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_TERMINAL_RIGHTS, key.toString());
        }
      }
      else if (key == EIDKeys.SPECIFIC_ATTRIBUTES || key == EIDKeys.DELETE_SPECIFIC_ATTRIBUTES)
      {
        input.setSpecificAttributes(key, true, request.getParametersSART());
      }
      else
      {
        input.addRequiredField(key);
      }
      if (key == EIDKeys.INSTALL_QUALIFIED_CERTIFICATE)
      {
        input.setCAConnection(new DummyCAConnection());
      }
    }

    for ( EIDKeys key : request.getOptionalFields() )
    {
      if (!isInAuth(key, auth))
      {
        throw new ErrorCodeException(ErrorCode.EID_MISSING_TERMINAL_RIGHTS, key.toString());
      }
      if (key == EIDKeys.AGE_VERIFICATION)
      {
        if (request.getRequestedMinAge() == 0)
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_ARGUMENT, "RequestedMinAge");
        }
        input.setAgeVerification(request.getRequestedMinAge(), false);
      }
      else if (key == EIDKeys.MUNICIPALITY_ID_VERIFICATION)
      {
        if (request.getRequestedCommunityIDPattern() == null)
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_ARGUMENT, "CommunityIDPattern");
        }
        input.setCommunityIDVerification(request.getRequestedCommunityIDPattern(), false);
      }
      else if (key == EIDKeys.PSM)
      {
        input.setPSM(request.getMessagePSM(), false);
      }
      else if (key == EIDKeys.PSC)
      {
        input.setPSC(request.getParametersPSC(), false);
        if (!this.checkFieldsForSignature(request.getParametersPSC(), auth))
        {
          throw new ErrorCodeException(ErrorCode.EID_MISSING_TERMINAL_RIGHTS, key.toString());
        }
      }
      else if (key == EIDKeys.SPECIFIC_ATTRIBUTES || key == EIDKeys.DELETE_SPECIFIC_ATTRIBUTES)
      {
        input.setSpecificAttributes(key, false, request.getParametersSART());
      }
      else
      {
        input.addOptionalField(key);
      }
      if (key == EIDKeys.INSTALL_QUALIFIED_CERTIFICATE)
      {
        input.setCAConnection(new DummyCAConnection());
      }
    }
  }

  private boolean isInAuth(EIDKeys key, Authorizations auth)
  {
    switch (key)
    {
      case DOCUMENT_TYPE:
        return auth.getEidAccess() == null ? auth.getChat().isReadDocumentType()
          : auth.getEidAccess().isReadDocumentType();
      case ISSUING_STATE:
        return auth.getEidAccess() == null ? auth.getChat().isReadIssuingState()
          : auth.getEidAccess().isReadIssuingState();
      case DATE_OF_EXPIRY:
        return auth.getEidAccess() == null ? auth.getChat().isReadDateOfExpiry()
          : auth.getEidAccess().isReadDateOfExpiry();
      case GIVEN_NAMES:
        return auth.getEidAccess() == null ? auth.getChat().isReadGivenNames()
          : auth.getEidAccess().isReadGivenNames();
      case FAMILY_NAMES:
        return auth.getEidAccess() == null ? auth.getChat().isReadFamilyNames()
          : auth.getEidAccess().isReadFamilyNames();
      case NOM_DE_PLUME:
        return auth.getEidAccess() == null ? auth.getChat().isReadNomDePlume()
          : auth.getEidAccess().isReadNomDePlume();
      case ACADEMIC_TITLE:
        return auth.getEidAccess() == null ? auth.getChat().isReadAcademicTitle()
          : auth.getEidAccess().isReadAcademicTitle();
      case DATE_OF_BIRTH:
        return auth.getEidAccess() == null ? auth.getChat().isReadDateOfBirth()
          : auth.getEidAccess().isReadDateOfBirth();
      case PLACE_OF_BIRTH:
        return auth.getEidAccess() == null ? auth.getChat().isReadPlaceOfBirth()
          : auth.getEidAccess().isReadPlaceOfBirth();
      case NATIONALITY:
        return auth.getEidAccess() == null ? auth.getChat().isReadNationality()
          : auth.getEidAccess().isReadNationality();
      case SEX:
        return auth.getEidAccess() == null ? auth.getChat().isReadSex() : auth.getEidAccess().isReadSex();
      case OPTIONAL_DATA_R:
        return auth.getEidAccess() == null ? auth.getChat().isReadOptionalDataR()
          : auth.getEidAccess().isReadOptionalDataR();
      case BIRTH_NAME:
        return auth.getEidAccess() == null ? auth.getChat().isReadBirthName()
          : auth.getEidAccess().isReadBirthName();
      case WRITTEN_SIGNATURE:
        return auth.getEidAccess() == null ? auth.getChat().isReadWrittenSignature()
          : auth.getEidAccess().isReadWrittenSignature();
      case DATE_OF_ISSUANCE:
        return auth.getEidAccess() == null ? auth.getChat().isReadDateOfIssuance()
          : auth.getEidAccess().isReadDateOfIssuance();
      case PLACE_OF_RESIDENCE:
        return auth.getEidAccess() == null ? auth.getChat().isReadPlaceOfResidence()
          : auth.getEidAccess().isReadPlaceOfResidence();
      case MUNICIPALITY_ID:
        return auth.getEidAccess() == null ? auth.getChat().isReadMunicipalityID()
          : auth.getEidAccess().isReadMunicipalityID();
      case RESIDENCE_PERMIT_I:
        return auth.getEidAccess() == null ? auth.getChat().isReadResidencePermitI()
          : auth.getEidAccess().isReadResidencePermitI();
      case RESIDENCE_PERMIT_II:
        return auth.getEidAccess() == null ? auth.getChat().isReadResidencePermitII()
          : auth.getEidAccess().isReadResidencePermitII();
      case PHONE_NUMBER:
        return auth.getEidAccess() == null ? auth.getChat().isReadPhoneNumber()
          : auth.getEidAccess().isReadPhoneNumber();
      case EMAIL_ADDRESS:
        return auth.getEidAccess() == null ? auth.getChat().isReadEmailAddress()
          : auth.getEidAccess().isReadEmailAddress();
      case DOCUMENT_VALIDITY:
        return false;
      case RESTRICTED_ID:
        return auth.getSpecialFunctions() == null ? auth.getChat().isAuthenticateRestrictedIdentification()
          : auth.getSpecialFunctions().isAuthenticateRestrictedIdentification();
      case AGE_VERIFICATION:
        return auth.getSpecialFunctions() == null ? auth.getChat().isAuthenticateAgeVerification()
          : auth.getSpecialFunctions().isAuthenticateAgeVerification();
      case MUNICIPALITY_ID_VERIFICATION:
        return auth.getSpecialFunctions() == null ? auth.getChat().isAuthenticateMunicipalityIDVerification()
          : auth.getSpecialFunctions().isAuthenticateMunicipalityIDVerification();
      case INSTALL_QUALIFIED_CERTIFICATE:
        return auth.getChat().isInstallQualifiedCertificate();
      case PSA:
        return auth.getSpecialFunctions() == null ? false
          : auth.getSpecialFunctions().isPerformPseudonymousSignatureAuthentication();
      case PSC:
        return auth.getSpecialFunctions() == null ? false
          : auth.getSpecialFunctions().isPerformPseudonymousSignatureCredentials();
      case PSM:
        return auth.getSpecialFunctions() == null ? false
          : auth.getSpecialFunctions().isPerformPseudonymousSignatureMessage();
      case SPECIFIC_ATTRIBUTES:
        return auth.getSpecificAttributes() == null ? false
          : auth.getSpecificAttributes().isAuthenticateWriteAttributeRequest()
            && auth.getSpecificAttributes().isAuthenticateReadSpecificAttributes();
      case DELETE_SPECIFIC_ATTRIBUTES:
        return auth.getSpecificAttributes() == null ? false
          : auth.getSpecificAttributes().isAuthenticateDeleteSpecificAttributes();
      case PROVIDE_SPECIFIC_ATTRIBUTES:
        return auth.getSpecificAttributes() == null ? false
          : auth.getSpecificAttributes().isAuthenticateReadAttributeRequest()
            && auth.getSpecificAttributes().isAuthenticateWriteSpecificAttributes();
      case PROVIDE_GLOBAL_GENERIC_ATTRIBUTES:
      default:
        break;
    }
    return false;
  }

  private boolean checkFieldsForSignature(PSCRequestType requestedFields, Authorizations auth)
  {
    ATEidAccess eidAccess = auth.getEidAccess();
    ATSpecificAttributes specAttributes = auth.getSpecificAttributes();
    if ((requestedFields.isDocumentType() != null && requestedFields.isDocumentType()
         && (eidAccess == null || !eidAccess.isPSCDocumentType()))
        || (requestedFields.isIssuingState() != null && requestedFields.isIssuingState()
            && (eidAccess == null || !eidAccess.isPSCIssuingState()))
        || (requestedFields.isDateOfExpiry() != null && requestedFields.isDateOfExpiry()
            && (eidAccess == null || !eidAccess.isPSCDateOfExpiry()))
        || (requestedFields.isGivenNames() != null && requestedFields.isGivenNames()
            && (eidAccess == null || !eidAccess.isPSCGivenNames()))
        || (requestedFields.isFamilyNames() != null && requestedFields.isFamilyNames()
            && (eidAccess == null || !eidAccess.isPSCFamilyNames()))
        || (requestedFields.isArtisticName() != null && requestedFields.isArtisticName()
            && (eidAccess == null || !eidAccess.isPSCNomDePlume()))
        || (requestedFields.isAcademicTitle() != null && requestedFields.isAcademicTitle()
            && (eidAccess == null || !eidAccess.isPSCAcademicTitle()))
        || (requestedFields.isDateOfBirth() != null && requestedFields.isDateOfBirth()
            && (eidAccess == null || !eidAccess.isPSCDateOfBirth()))
        || (requestedFields.isPlaceOfBirth() != null && requestedFields.isPlaceOfBirth()
            && (eidAccess == null || !eidAccess.isPSCPlaceOfBirth()))
        || (requestedFields.isNationality() != null && requestedFields.isNationality()
            && (eidAccess == null || !eidAccess.isPSCNationality()))
        || (requestedFields.isSex() != null && requestedFields.isSex()
            && (eidAccess == null || !eidAccess.isPSCSex()))
        || (requestedFields.isOptionalDataR() != null && requestedFields.isOptionalDataR()
            && (eidAccess == null || !eidAccess.isPSCOptionalDataR()))
        || (requestedFields.isBirthName() != null && requestedFields.isBirthName()
            && (eidAccess == null || !eidAccess.isPSCBirthName()))
        || (requestedFields.isWrittenSignature() != null && requestedFields.isWrittenSignature()
            && (eidAccess == null || !eidAccess.isPSCWrittenSignature()))
        || (requestedFields.isDateOfIssuance() != null && requestedFields.isDateOfIssuance()
            && (eidAccess == null || !eidAccess.isPSCDateOfIssuance()))
        || (requestedFields.isPlaceOfResidence() != null && requestedFields.isPlaceOfResidence()
            && (eidAccess == null || !eidAccess.isPSCPlaceOfResidence()))
        || (requestedFields.isMunicipalityID() != null && requestedFields.isMunicipalityID()
            && (eidAccess == null || !eidAccess.isPSCMunicipalityID()))
        || (requestedFields.isResidencePermitI() != null && requestedFields.isResidencePermitI()
            && (eidAccess == null || !eidAccess.isPSCResidencePermitI()))
        || (requestedFields.isResidencePermitII() != null && requestedFields.isResidencePermitII()
            && (eidAccess == null || !eidAccess.isPSCResidencePermitII()))
        || (requestedFields.isPhoneNumber() != null && requestedFields.isPhoneNumber()
            && (eidAccess == null || !eidAccess.isPSCPhoneNumber()))
        || (requestedFields.isEmailAddress() != null && requestedFields.isEmailAddress()
            && (eidAccess == null || !eidAccess.isPSCEmailAddress()))
        || (requestedFields.isSpecificAttribute() != null && requestedFields.isSpecificAttribute()
            && (specAttributes == null || !specAttributes.isAuthenticateIncludeSpecificAttributesToPSC())))
    {
      return false;
    }
    return true;
  }

  private TerminalPermissionAO cvcFacade;

  public void setCVCFacade(TerminalPermissionAO facade)
  {
    this.cvcFacade = facade;
  }

  /**
   * Gives back the data that was ordered to the client. Will usually be called more than one time.
   * 
   * @param requestId
   * @return the result or an error-message
   */
  public EIDResultResponse getResult(String requestId, int requestCounter)
  {
    LOG.debug("started getResult(GetResultRequest)");
    EIDSession session = null;
    if (requestId != null)
    {
      session = sessionManager.getByRequestId(requestId, EIDSession.class);
    }
    if (session == null)
    {
      return new EIDResultResponse(null, Constants.EID_MAJOR_ERROR,
                                   Constants.EID_MINOR_GETRESULT_INVALID_SESSION, null,
                                   "<unknown>: " + requestId + ": ");
    }
    if (session.getSequenceNumber() != null && requestCounter != session.getSequenceNumber() + 1)
    {
      sessionManager.remove(session);
      return new EIDResultResponse(null, Constants.EID_MAJOR_ERROR,
                                   Constants.EID_MINOR_GETRESULT_INVALID_COUNTER, null,
                                   session.getLogPrefix());
    }
    session.setSequenceNumber(requestCounter);
    Result result = session.getResult();
    if (result == null)
    {
      try
      {
        sessionManager.store(session);
      }
      catch (ErrorCodeException e)
      {
        LOG.error(session.getLogPrefix() + "Can not store session", e);
        return new EIDResultResponse(null, Constants.EID_MAJOR_ERROR,
                                     Constants.EID_MINOR_COMMON_INTERNALERROR, null, session.getLogPrefix());
      }
      return new EIDResultResponse(null, Constants.EID_MAJOR_ERROR,
                                   Constants.EID_MINOR_GETRESULT_NO_RESULT_YET, null, session.getLogPrefix());
    }
    EIDResultResponse response = new EIDResultResponse(session.getStatus(), session.getResult(),
                                                       session.getInfoMap(), session.getLogPrefix());
    if (session.isDemoDataEnabled())
    {
      response.setResultMessage("This response contains test data only.");
    }
    sessionManager.remove(session);
    return response;
  }

  private boolean ageVerificationRequestIncomplete(EIDRequestInput request)
  {
    return (request.getRequiredFields().contains(EIDKeys.AGE_VERIFICATION)
            || request.getOptionalFields().contains(EIDKeys.AGE_VERIFICATION))
           && request.getRequestedMinAge() <= 0;
  }

  private boolean placeVerificationRequestIncomplete(EIDRequestInput request)
  {
    return (request.getRequiredFields().contains(EIDKeys.MUNICIPALITY_ID_VERIFICATION)
            || request.getOptionalFields().contains(EIDKeys.MUNICIPALITY_ID_VERIFICATION))
           && request.getRequestedCommunityIDPattern() == null;
  }

  private boolean psmRequestIncomplete(EIDRequestInput request)
  {
    return (request.getRequiredFields().contains(EIDKeys.PSM)
            || request.getOptionalFields().contains(EIDKeys.PSM))
           && request.getMessagePSM() == null;
  }

  private boolean pscRequestIncomplete(EIDRequestInput request)
  {
    return (request.getRequiredFields().contains(EIDKeys.PSC)
            || request.getOptionalFields().contains(EIDKeys.PSC))
           && request.getParametersPSC() == null;
  }

  private boolean specificAttributeRequestIncomplete(EIDRequestInput request)
  {
    return (request.getRequiredFields().contains(EIDKeys.SPECIFIC_ATTRIBUTES)
            || request.getOptionalFields().contains(EIDKeys.SPECIFIC_ATTRIBUTES))
           && (request.getParametersSART() == null
               || request.getParametersSART().getAttributeRequest() == null
               || request.getParametersSART().getAttributeRequest().length == 0);
  }

}
