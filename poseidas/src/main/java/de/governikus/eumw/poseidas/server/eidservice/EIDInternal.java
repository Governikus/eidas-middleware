/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDSequence.Authorizations;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerFactory;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerI;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.server.idprovider.core.AuthenticationSessionManager;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.RequiredArgsConstructor;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Functional implementation of the eID-interface. This class provides an API which can be used from inside
 * the server instead of the WebService interface.
 *
 * @author CM, TT
 * @author hauke
 */

@Component
@RequiredArgsConstructor
public class EIDInternal
{

  private static final String COLON_AND_SPACE = ": ";

  private static final Log LOG = LogFactory.getLog(EIDInternal.class);

  private final AuthenticationSessionManager sessionManager = AuthenticationSessionManager.getInstance();

  private boolean initDone = false;

  private final TerminalPermissionAO cvcFacade;

  private final BlockListService blockListService;

  private static X509Certificate tryGenerateCertFromZip(String logPrefix,
                                                        CertificateFactory certFactory,
                                                        ZipInputStream zis)
  {
    try
    {
      return (X509Certificate)certFactory.generateCertificate(zis);
    }
    catch (CertificateException e)
    {
      if (LOG.isInfoEnabled())
      {
        LOG.info(logPrefix + "Can not read a certificate from the master list zip file.", e);
      }
      return null;
    }
  }

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
   * Perform a useID-Request as described in the WSDL.
   *
   * @param request describes the requested data
   * @param client identifies the provider by used SSL client certificate
   * @return {@link EIDRequestResponse} contains session id and pre-shared key
   */
  public EIDRequestResponse useID(EIDRequestInput request, ServiceProviderType client)
  {
    if (client != null)
    {
      LOG.debug("identified client " + client.getName());
    }
    else
    {
      LOG.error("called useID() without client");
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
    EIDRequestResponse errorResponse = checkRequestError(request, sessionId, requestId, client);
    if (errorResponse != null)
    {
      return errorResponse;
    }
    EIDSession mySession = new EIDSession(sessionId, requestId, client.getName());
    EIDRequestResponse response = new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_OK, null,
                                                         null,
                                                         mySession.getLogPrefix());

    try
    {
      SessionInput input = startEcardApiRequest(mySession,
                                                request,
                                                client.getCVCRefID());
      ECardIDServerFactory.getInstance().getCurrentServer();
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
                                    e.getMessage(), mySession.getLogPrefix());
    }
    catch (IllegalArgumentException e)
    {
      LOG.info(mySession.getLogPrefix() + "an internal error occurred while processing a request", e);
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR, e.getMessage(),
                                    mySession.getLogPrefix());
    }
    return response;
  }

  private EIDRequestResponse checkRequestError(EIDRequestInput request,
                                               String sessionId,
                                               String requestId,
                                               ServiceProviderType client)
  {
    if (client == null)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR,
                                    "client is unknown in the configuration",
                                    "<unknown>: " + requestId + COLON_AND_SPACE);
    }
    if (!client.isEnabled())
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR, "client is disabled",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
    }
    if (!blockListService.hasBlockList(client.getCVCRefID()))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_COMMON_INTERNALERROR, "client has no blocklist",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
    }
    if (sessionId == null || sessionId.length() < 16 || sessionId.length() > 10240)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "The session Id it too short with " + ((sessionId == null) ? 0
                                      : sessionId.length()) + " bytes",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
    }
    if (requestId == null || requestId.length() < 16 || requestId.length() > 10240)
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "The Request ID it too short with " + ((requestId == null) ? 0
                                      : requestId.length()) + " bytes",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
    }
    if (ageVerificationRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify required age to perform age verification",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
    }
    if (placeVerificationRequestIncomplete(request))
    {
      return new EIDRequestResponse(sessionId, requestId, Constants.EID_MAJOR_ERROR,
                                    Constants.EID_MINOR_USEID_MISSING_ARGUMENT,
                                    "must specify communityId to check against",
                                    client.getName() + COLON_AND_SPACE + requestId + COLON_AND_SPACE);
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
                                            EIDRequestInput request,
                                            String refId)
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
      input = new SessionInputImpl(cvc, tp.getCvcChain(), session.getSessionId(),

                                   new BlackListConnectorImpl(blockListService, tp.getSectorID()), masterListCerts,
                                   defectListData, request.getTransactionInfo(), session.getLogPrefix());
    }
    else
    {
      input = new SessionInputImpl(cvc, tp.getCvcChain(), session.getSessionId(),

                                   new BlackListConnectorImpl(blockListService, tp.getSectorID()), masterListData,
                                   defectListData, request.getTransactionInfo(), session.getLogPrefix());
    }
    translateSelector(request, input, cvc.getAuthorizations());

    return input;
  }

  private boolean isZipData(byte[] data)
  {
    return data[0] == 0x50 && data[1] == 0X4b;
  }

  private List<X509Certificate> addMasterListCertsFromZip(byte[] listData, String logPrefix)
  {
    CertificateFactory certFactory = null;
    try
    {
      certFactory = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    catch (CertificateException e)
    {
      // without certificate factory the is little we can do
      return Collections.emptyList();
    }

    List<X509Certificate> result = new ArrayList<>();
    try (ZipInputStream ins = new ZipInputStream(new ByteArrayInputStream(listData)))
    {
      while (ins.getNextEntry() != null)
      {
        X509Certificate cert = tryGenerateCertFromZip(logPrefix, certFactory, ins);
        if (cert != null)
        {
          result.add(cert);
        }
      }
      return result;
    }
    catch (IOException e)
    {
      LOG.error(logPrefix + "fake masterlist not readable", e);
    }
    return Collections.emptyList();
  }

  private void translateSelector(EIDRequestInput request, SessionInputImpl input, Authorizations auth)
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
      else
      {
        input.addRequiredField(key);
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
      else
      {
        input.addOptionalField(key);
      }
    }
  }

  private boolean isInAuth(EIDKeys key, Authorizations auth)
  {
    switch (key)
    {
      case DOCUMENT_TYPE:
        return auth.getChat().isReadDocumentType();
      case ISSUING_STATE:
        return auth.getChat().isReadIssuingState();
      case DATE_OF_EXPIRY:
        return auth.getChat().isReadDateOfExpiry();
      case GIVEN_NAMES:
        return auth.getChat().isReadGivenNames();
      case FAMILY_NAMES:
        return auth.getChat().isReadFamilyNames();
      case NOM_DE_PLUME:
        return auth.getChat().isReadNomDePlume();
      case ACADEMIC_TITLE:
        return auth.getChat().isReadAcademicTitle();
      case DATE_OF_BIRTH:
        return auth.getChat().isReadDateOfBirth();
      case PLACE_OF_BIRTH:
        return auth.getChat().isReadPlaceOfBirth();
      case NATIONALITY:
        return auth.getChat().isReadNationality();
      case SEX:
        return auth.getChat().isReadSex();
      case OPTIONAL_DATA_R:
        return auth.getChat().isReadOptionalDataR();
      case BIRTH_NAME:
        return auth.getChat().isReadBirthName();
      case WRITTEN_SIGNATURE:
        return auth.getChat().isReadWrittenSignature();
      case DATE_OF_ISSUANCE:
        return auth.getChat().isReadDateOfIssuance();
      case PLACE_OF_RESIDENCE:
        return auth.getChat().isReadPlaceOfResidence();
      case MUNICIPALITY_ID:
        return auth.getChat().isReadMunicipalityID();
      case RESIDENCE_PERMIT_I:
        return auth.getChat().isReadResidencePermitI();
      case RESIDENCE_PERMIT_II:
        return auth.getChat().isReadResidencePermitII();
      case PHONE_NUMBER:
        return auth.getChat().isReadPhoneNumber();
      case EMAIL_ADDRESS:
        return auth.getChat().isReadEmailAddress();
      case DOCUMENT_VALIDITY:
        return false;
      case RESTRICTED_ID:
        return auth.getChat().isAuthenticateRestrictedIdentification();
      case AGE_VERIFICATION:
        return auth.getChat().isAuthenticateAgeVerification();
      case MUNICIPALITY_ID_VERIFICATION:
        return auth.getChat().isAuthenticateMunicipalityIDVerification();
      default:
        break;
    }
    return false;
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
                                   "<unknown>: " + requestId + COLON_AND_SPACE);
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
}
