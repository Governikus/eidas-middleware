/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBElement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ASN1EidConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccess;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccessConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialFunctions;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributes;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescriptionPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate.ChatTerminalType;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;
import de.governikus.eumw.poseidas.cardserver.eac.protocol.EACFinal;
import de.governikus.eumw.poseidas.cardserver.eac.protocol.EACServer;
import de.governikus.eumw.poseidas.cardserver.eac.protocol.InvalidEidException;
import de.governikus.eumw.poseidas.ecardcore.core.ECardException;
import de.governikus.eumw.poseidas.ecardcore.model.EAC1InputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC1OutputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC2InputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.EAC2OutputTypeWrapper;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidmodel.AuthenticatedAuxiliaryData;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.session.SessionManager;
import de.governikus.eumw.poseidas.eidserver.eac.EACSignedDataChecker;
import de.governikus.eumw.poseidas.eidserver.eac.EACSignedDataController;
import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerFactory;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerI;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectKnown.DefectType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectList;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticate;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticateResponse;
import iso.std.iso_iec._24727.tech.schema.DIDAuthenticationDataType;
import iso.std.iso_iec._24727.tech.schema.EAC1OutputType;
import iso.std.iso_iec._24727.tech.schema.EAC2OutputType;
import iso.std.iso_iec._24727.tech.schema.ExtendedAccessPermission;
import iso.std.iso_iec._24727.tech.schema.ResponseType;
import iso.std.iso_iec._24727.tech.schema.StartPAOS;
import iso.std.iso_iec._24727.tech.schema.StartPAOS.UserAgent;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import oasis.names.tc.dss._1_0.core.schema.ObjectFactory;
import oasis.names.tc.dss._1_0.core.schema.Result;



/**
 * EIDSequence tries to do an EAC protocol with a remote card and ask for some information from the card,
 * described by the SessionInput.
 * <p>
 * <ol>
 * <li>Start sequence required data to start</li>
 * <li>Authenticate</li>
 * <li>Transmits for verification</li>
 * <li>Transmits for card data</li>
 * <li>End sequence</li>
 * </ol>
 * </p>
 * <p>
 * After Authentication the first Transmit starts. For every Transmit request a response is received and
 * analyzed. If the content is as expected, new requests are send until all required informations are
 * received.
 * <p>
 * <p>
 * MCard provides TransmitBatches to handle more than one command per transmit.
 *
 * @author Alexander Funk
 * @author Ole Behrens
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 * @see SessionInput
 */
public class EIDSequence extends ECardConvenienceSequenceAdapter
{

  /**
   * LOGGER for this class. Note: Data fields should be logged only in LEVEL.TRACE
   */
  private static final Log LOG = LogFactory.getLog(EIDSequence.class.getName());

  /**
   * Logging prefix
   */
  private static final String LOG_PRE = "[de.governikus.eumw.poseidas.eidserver.convenience.EIDSequence] ";

  /**
   * Static provider for keys and certificates
   */
  private static CertAndKeyProviderImpl cakProvider = new CertAndKeyProviderImpl();

  /**
   * Statics for readable logs
   */
  private static final String LOG_PRE_INIT = "[SEQUENCE INIT] ";

  private static final String LOG_PRE_START = "[SEQUENCE START] ";

  private static final String LOG_PRE_AUTH = "[SEQUENCE AUTHENTICATION] ";

  private static final String LOG_PRE_END = "[SEQUENCE END]";

  private static final String DEFAULT_DID_NAME = "PIN";

  // ================ COMPLEX TYPES ================

  /**
   * Class to handle transmit process
   */
  private EIDSequenceTransmit transmitProcess;

  /**
   * Card Holder Authentication Template with required fields for this instance
   */
  private final Authorizations mRequiredAuthorizations = new Authorizations();

  /**
   * Card Holder Authentication Template with optional fields for this instance
   */
  private final Authorizations mOptionalAuthorizations = new Authorizations();

  /**
   * Card Holder Authentication Template with fields selected by user
   */
  private final Authorizations mModifiedAuthorizations = new Authorizations();

  /**
   * Card Verifiable Certificate for this instance and transmit process
   */
  private TerminalData mCardVerifiableCert;

  private List<TerminalData> cvcList;

  /**
   * Connection where card communicates
   */
  private ConnectionHandleType mConnectionHandle;

  /**
   * Informations collected while processing sequence
   */
  private final EIDInfoContainerImpl eidInfoContainer;

  /**
   * Server from mCard to handle EACInput/Output
   */
  private EACServer eacServer;

  /**
   * EAC1InputType stored to create the following EACTypes
   */
  private EAC1InputTypeWrapper eac1Input;

  /**
   * Result stored to handle restricted/blocking id
   */
  private EACFinal result;

  /**
   * MasterList checks are handled with this instance for mCard
   */
  private EACSignedDataChecker signedDataChecker;

  /**
   * DefectList checks are handled with this instance
   */
  private EACSignedDataController controller;

  /**
   * Defect list class
   */
  private DefectList defectList;

  /**
   * Additional checks
   */
  private AuthenticatedAuxiliaryData authenticatedAuxiliaryData;

  /**
   * Anchor for response and requests
   */
  private Object returnObject;

  /**
   * Data fields to be read
   */
  private Set<CVCPermission> allRights;


  // ================ SIMPLE TYPES ================

  /**
   * Selected IFD name from list
   */
  private String mIFDName;

  /**
   * PIN or CAN for card authorization
   */
  private String mDIDName;

  private String logPrefix;

  /**
   * Indicates if a startPAOS was received so other messages can follow
   */
  private boolean startPAOSReceived;

  /**
   * Indicates if all data is read from card
   */
  private boolean finished;

  /**
   * Input to session.
   */
  private SessionInput sessionInput;

  /**
   * Initialized provider for this Class.
   *
   * @return static provider certificates and keys
   */
  public static CertAndKeyProviderImpl getCakProvider()
  {
    return cakProvider;
  }

  /**
   * EIDSequence object to handle EAC protocol with nPA
   *
   * @param frameworkInstance for eCard
   * @param cvc represents the card verifiable certificate from mCard
   * @param cvcList represents the card verifiable certificate from mCard and the link certificates from
   *          server
   * @param requiredChat CHAT for this session
   * @param optionalChat CHAT for this session
   * @param sessionInput for this sequence
   * @throws IllegalArgumentException is thrown if no Blacklist is available or sessionInput returns
   *           unexpected result
   */
  public EIDSequence(TerminalData cvc, List<TerminalData> cvcList, SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    super();
    setInstanceCVC(cvc, cvcList);
    setInstanceSession(sessionInput);
    this.mRequiredAuthorizations.chat = createRequiredCHAT(sessionInput);
    this.mOptionalAuthorizations.chat = createOptionalCHAT(sessionInput);
    this.mRequiredAuthorizations.specialFunctions = createRequiredSF(sessionInput);
    this.mOptionalAuthorizations.specialFunctions = createOptionalSF(sessionInput);
    this.mRequiredAuthorizations.eidAccess = createRequiredATeID(sessionInput);
    this.mOptionalAuthorizations.eidAccess = createOptionalATeID(sessionInput);
    this.mRequiredAuthorizations.specificAttributes = createRequiredSpecificAttributes(sessionInput);
    this.mOptionalAuthorizations.specificAttributes = createOptionalSpecificAttributes(sessionInput);
    // Set container for data received from card
    eidInfoContainer = new EIDInfoContainerImpl();
    LOG.debug(logPrefix + LOG_PRE_INIT + "Instance (ECardConvenienceSequenceAdapter) available");
  }

  private void setInstanceCVC(TerminalData cvc, List<TerminalData> cvcList)
  {
    // Check CVC
    if (cvcList == null || cvc == null)
    {
      throw new IllegalArgumentException(LOG_PRE_INIT + "Initialize fail: " + "CVC is null");
    }
    // First CVC from list is the terminal certificate
    mCardVerifiableCert = cvc;
    CertificateDescription cvcDescription = mCardVerifiableCert.getCVCDescription();
    // Check description
    if (cvcDescription == null)
    {
      throw new IllegalArgumentException(LOG_PRE_INIT + "Initialize fail: " + "CVC description is null");
    }
    try
    {
      ASN1 commonCertificates = cvcDescription.getCertificateDescriptionPart(CertificateDescriptionPath.COMM_CERTIFICATES);
      if (commonCertificates != null)
      {
        LOG.debug(logPrefix + LOG_PRE_INIT + "Common certificates length: "
                  + commonCertificates.getChildElementCount());
      }
      else
      {
        throw new IllegalArgumentException(LOG_PRE_INIT + "CVC contains not the required descriptions: "
                                           + "No common certificates found");
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException(LOG_PRE_INIT + "CVC contains not the required descriptions", e);
    }
    this.cvcList = cvcList;
  }

  private void setInstanceController(byte[] efCardSecurity) throws IOException
  {
    controller = new EACSignedDataController(efCardSecurity, defectList, logPrefix);
    if (controller.containDefects())
    {
      LOG.debug(logPrefix + LOG_PRE_AUTH + "Card affected by defects");
    }
    else
    {
      LOG.debug(logPrefix + LOG_PRE_AUTH + "Card not affected by defects");
    }
  }

  /**
   * Sets a session in sequence
   *
   * @param sessionInput
   */
  private void setInstanceSession(SessionInput sessionInput)
  {
    if (sessionInput != null)
    {
      logPrefix = sessionInput.getLogPrefix();
      try
      {
        sessionInput.getBlackListConnector();
      }
      catch (NullPointerException e)
      {
        LOG.warn(logPrefix + "[SERVER] blacklist not available");
        throw new IllegalArgumentException(LOG_PRE_INIT + "Initialize fail: "
                                           + "BlacklistConnector is not available");
      }

      if (sessionInput.getSessionID() == null)
      {
        throw new IllegalArgumentException(LOG_PRE_INIT + "No session ID found for session input");
      }
      setInstanceAuxiliaryData(sessionInput);
    }
    else
    {
      throw new IllegalArgumentException(LOG_PRE_INIT + "Initialize fail: "
                                         + "To provide preshared key and hash for SAML request"
                                         + " session input is required");
    }

    List<X509Certificate> masterList = getMasterList(sessionInput);
    LOG.debug(logPrefix + LOG_PRE_INIT + " MasterList received from manager containing (" + masterList.size()
              + ") Certificates");
    signedDataChecker = new EACSignedDataChecker(masterList, logPrefix);
    if (sessionInput.getDefectList() != null)
    {
      defectList = new DefectList(sessionInput.getDefectList());
      LOG.debug(logPrefix + LOG_PRE_INIT + " DefectList received from manager containing ("
                + defectList.size() + ") defects");
    }
    else
    {
      LOG.debug(logPrefix + LOG_PRE_INIT + " No DefectList received from manager");
    }
    this.sessionInput = sessionInput;
  }

  private void setInstanceAuxiliaryData(SessionInput sessionInput)
  {
    authenticatedAuxiliaryData = new AuthenticatedAuxiliaryData();
    Date now = new Date();
    if (sessionInput.getRequiredAge() != null)
    {
      Calendar calendar = Calendar.getInstance();
      calendar.setTime(now);
      if (sessionInput.getRequiredAge() <= 0)
      {
        throw new IllegalArgumentException(LOG_PRE_INIT + "Required age must be greater than 0");
      }
      calendar.add(Calendar.YEAR, -1 * sessionInput.getRequiredAge());
      String ageVerification = new SimpleDateFormat("yyyyMMdd").format(calendar.getTime());
      authenticatedAuxiliaryData.setAgeVerificationAuxiliaryData(ageVerification);
    }
    if (sessionInput.getRequiredCommunity() != null)
    {
      authenticatedAuxiliaryData.setCommunityIDAuxiliaryData(sessionInput.getRequiredCommunity());
    }
    if (sessionInput.getPsMessage() != null)
    {
      // per specification we are required to set the hash of the message here, but we cannot know the
      // algorithm...
      byte[] psMessage = null;
      try
      {
        psMessage = MessageDigest.getInstance("SHA-256").digest(sessionInput.getPsMessage());
      }
      catch (NoSuchAlgorithmException e)
      {
        psMessage = sessionInput.getPsMessage();
      }
      this.authenticatedAuxiliaryData.setPseudonymousSignatureMessage(psMessage);
    }
    String documentVerification = new SimpleDateFormat("yyyyMMdd").format(now);
    LOG.debug(logPrefix + LOG_PRE_INIT + "Document Validity will be checked for date: "
              + documentVerification);
    authenticatedAuxiliaryData.setDocumentVerificationAuxiliaryData(documentVerification);
  }

  private List<X509Certificate> getMasterList(SessionInput sessionInput)
  {
    if (sessionInput.getMasterList() != null)
    {
      if (sessionInput.getMasterList().length < 1)
      {
        throw new IllegalArgumentException("Master list to set may not be empty");
      }

      MasterList masterListObj = new MasterList(sessionInput.getMasterList());
      List<X509Certificate> certificates = masterListObj.getCertificates();
      if (certificates.isEmpty())
      {
        throw new IllegalArgumentException("Master list is empty");
      }
      return certificates;
    }
    else if (sessionInput.getMasterListCerts() != null)
    {
      return sessionInput.getMasterListCerts();
    }
    else
    {
      throw new IllegalArgumentException("no Master List given in SessionInput");
    }
  }

  /**
   * All informations created by this sequence are stored here
   *
   * @return Container with required informations
   */
  public EIDInfoContainerImpl getEIDInfoContainer()
  {
    return eidInfoContainer;
  }

  @Override
  public Object getNextRequest(ResponseType response)
  {
    // Reset the return object for every request
    returnObject = null;
    try
    {
      // Check if sequence has valid state
      if (!isStarted())
      {
        throw new ECardException(ResultMinor.COMMON_NO_PERMISSION, "Received no correct StartPAOS message");
      }

      // Check if result is OK or end response should be send
      if (response != null && !ResultMajor.OK.toString().equals(response.getResult().getResultMajor()))
      {
        throw new ECardException(response.getResult());
      }

      // as response to StartPAOS, send DIDAuthenticate(EAC1Input)
      if (response == null)
      {
        return handleStart();
      }

      // ===================================
      // DIDAuthenticate Response
      // ===================================
      if (response instanceof DIDAuthenticateResponse)
      {
        return handleDIDAuthenticate((DIDAuthenticateResponse)response);
      }
      // ==============================
      // Transmit Response
      // ==============================
      if (response instanceof TransmitResponse)
      {
        return handleTransmit((TransmitResponse)response);
      }
      // ==============================
      // UNKNOWN Response
      // ==============================
      return handleError(ResultMinor.COMMON_INTERNAL_ERROR, "Unknown response: terminate sequence");
    }
    // ==============================
    // Caught Exceptions
    // ==============================
    catch (ECardException e)
    {
      LOG.debug(logPrefix + e.toString(), e);
      Result resultFromException = e.getResult();
      Result handle = resultFromException;
      if (ResultMajor.OK.toString().equals(resultFromException.getResultMajor()))
      {
        handle.setResultMessage(ECardCoreUtil.generateInternationalStringType("Unexpected Error state (ResultMajor:OK) while: "
                                                                              + resultFromException.getResultMessage()));
      }
      if (resultFromException.getResultMinor() == null)
      {
        handle.setResultMinor(ResultMinor.COMMON_INTERNAL_ERROR.toString());
      }
      if (resultFromException.getResultMessage() == null)
      {
        handle.setResultMessage(ECardCoreUtil.generateInternationalStringType(e.getLocalizedMessage()));
      }

      ResultMinor rm;
      try
      {
        rm = ResultMinor.valueOfEnum(handle.getResultMinor());
      }
      catch (IllegalArgumentException | NullPointerException e2)
      {
        rm = ResultMinor.COMMON_INTERNAL_ERROR;
      }
      return handleError(rm,
                         handle.getResultMessage() == null || handle.getResultMessage().getValue() == null
                           ? "no message" : handle.getResultMessage().getValue());
    }
    // ==============================
    // Stop Session
    // ==============================
    finally
    {
      if (returnObject instanceof JAXBElement<?>
          && "StartPAOSResponse".equals(((JAXBElement<?>)returnObject).getName().getLocalPart()))
      {
        LOG.debug(logPrefix + LOG_PRE_END + "Session will be closed");
        LOG.debug(logPrefix + LOG_PRE_END + "Send StartPAOSResponse");

        ECardIDServerI currentServer = ECardIDServerFactory.getInstance().getCurrentServer();
        if (currentServer instanceof SessionManager)
        {
          ((SessionManager)currentServer).stopSession(this.sessionInput.getSessionID(), eidInfoContainer);
          LOG.debug(logPrefix + LOG_PRE_END + "Session '" + this.sessionInput.getSessionID()
                    + "' stopped by Manager >>> ");
        }
        else
        {
          LOG.debug(logPrefix + LOG_PRE_END
                    + "Session could not be stopped, because no session manager received from factory");
        }
        finished = true;
      }
    }
  }

  /**
   * Get the connection handle set for process
   *
   * @return connection handle
   */
  protected ConnectionHandleType getConnectionHandle()
  {
    return mConnectionHandle;
  }

  /**
   * Get the connector provided by the poseidas server
   *
   * @return connector providing blacklist informations
   */
  protected BlackListConnector getConnector()
  {
    return this.sessionInput.getBlackListConnector();
  }

  /**
   * Get the CVC for card
   *
   * @return CVC
   */
  protected TerminalData getCVC()
  {
    return mCardVerifiableCert;
  }

  /**
   * Get the result for EACFinal
   *
   * @return the result for EACFinal
   */
  protected EACFinal getEACFinal()
  {
    return result;
  }

  SessionInput getSessionInput()
  {
    return this.sessionInput;
  }

  /**
   * Indicates if this sequence should handle defects for this card
   *
   * @return true if defects should appear
   */
  public boolean isCardDefect()
  {
    if (controller != null)
    {
      return controller.containDefects();
    }
    else
    {
      return false;
    }
  }

  @Override
  public boolean isFinished()
  {
    return finished;
  }

  /**
   * Indicates if a startPAOS message was received from client
   *
   * @return true if message received
   */
  public boolean isStarted()
  {
    return startPAOSReceived;
  }

  /**
   * To start communication by PAOS a start message is required
   *
   * @param startPAOS to begin process
   * @throws IOException
   */
  public void setStart(StartPAOS startPAOS)
  {
    if (startPAOS == null)
    {
      LOG.error(LOG_PRE_START + "StartPAOS is null");
      return;
    }
    if (startPAOSReceived)
    {
      LOG.error(LOG_PRE_START + "StartPAOS already set");
      return;
    }
    String waitForConnectionHandle = "No connection handle for card reader available in StartPAOS. "
                                     + "Connection handle must be set later in process";
    List<ConnectionHandleType> connectionHandleList = startPAOS.getConnectionHandle();
    if (connectionHandleList != null)
    {
      int handlesCount = connectionHandleList.size();
      LOG.debug(logPrefix + LOG_PRE_START + "Connection handles available: " + handlesCount);
      // This should be the default case
      if (handlesCount == 1)
      {
        mConnectionHandle = connectionHandleList.get(0);
        mIFDName = mConnectionHandle.getIFDName();
        LOG.debug(logPrefix + LOG_PRE_START + "IFD name taken from StartPAOS connection handle: " + mIFDName);
      }
      else if (handlesCount > 1)
      {
        LOG.error(LOG_PRE_START + "More than one ConnectionHandle is not allowed for process");
        return;
      }
      else if (handlesCount < 1)
      {
        LOG.debug(logPrefix + LOG_PRE_START + waitForConnectionHandle);
      }
    }
    else
    {
      LOG.debug(logPrefix + LOG_PRE_START + waitForConnectionHandle);
    }
    UserAgent userAgent = startPAOS.getUserAgent();
    if (userAgent == null)
    {
      LOG.info(logPrefix + LOG_PRE_START + "No user agent information received");
    }
    else
    {
      LOG.info(logPrefix + LOG_PRE_START + "User agent on client side:\n" + userAgent);
    }
    startPAOSReceived = true;
  }

  /**
   * At start create a initialize framework
   *
   * @return factory object
   */
  private Object handleStart() throws ECardException
  {
    LOG.debug(logPrefix + LOG_PRE_START + "Connection handle available. DIDName set directly to 'PIN'");
    mDIDName = DEFAULT_DID_NAME;
    returnObject = getEAC1DIDAuthenticate();
    LOG.debug(logPrefix + "  Response > create DIDAuthenticate directly");
    return returnObject;
  }

  private Object handleDIDAuthenticate(DIDAuthenticateResponse response) throws ECardException
  {
    DIDAuthenticateResponse didAuthenticateResponse = response;
    // Check if it is an EAC1 or EAC2 response.
    DIDAuthenticationDataType protocolData = didAuthenticateResponse.getAuthenticationProtocolData();
    if (protocolData instanceof EAC1OutputType)
    {
      return handleAuthenticationProtocolData(new EAC1OutputTypeWrapper((EAC1OutputType)protocolData));
    }
    else if (protocolData instanceof EAC2OutputType)
    {
      return handleAuthenticationProtocolData(new EAC2OutputTypeWrapper((EAC2OutputType)protocolData));
    }
    else
    {
      return handleError(ResultMinor.COMMON_INTERNAL_ERROR,
                         "DIDAuthenticateResponse: authenticationProtocolData is no instanceof "
                                                           + "EAC1OutputType or EAC2OutputType");
    }
  }

  private Object handleAuthenticationProtocolData(EAC1OutputTypeWrapper eac1OutputType) throws ECardException
  {
    // Create Server and get stored EAC1Input
    eacServer = new EACServer();

    // Get selected fields from user
    byte[] template = eac1OutputType.getCertificateHolderAuthorizationTemplate();
    try
    {
      if (template != null)
      {
        this.mModifiedAuthorizations.chat = new CertificateHolderAuthorizationTemplate(template);
      }
      for ( ExtendedAccessPermission eap : eac1OutputType.getGrantedPermissionList() )
      {
        if (ATSpecialConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIAL_FUNCTIONS.equals(eap.getType()))
        {
          this.mModifiedAuthorizations.specialFunctions = new ATSpecialFunctions(new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA,
                                                                                          eap.getValue()).getEncoded());
        }
        else if (ATEidAccessConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_EID_ACCESS.equals(eap.getType()))
        {
          this.mModifiedAuthorizations.eidAccess = new ATEidAccess(new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA,
                                                                            eap.getValue()).getEncoded());
        }
        else if (ATSpecificAttributesConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIFIC_ATTRIBUTES.equals(eap.getType()))
        {
          this.mModifiedAuthorizations.specificAttributes = new ATSpecificAttributes(new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA,
                                                                                              eap.getValue()).getEncoded());
        }
      }
    }
    catch (IOException | IllegalArgumentException e)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, e);
    }
    if (this.mModifiedAuthorizations.chat != null)
    {
      this.allRights = this.mModifiedAuthorizations.chat.getAllRights();
    }
    else
    {
      this.allRights = this.mRequiredAuthorizations.chat.getAllRights();
      this.allRights.addAll(this.mOptionalAuthorizations.chat.getAllRights());
    }
    if (this.mModifiedAuthorizations.specialFunctions != null)
    {
      this.allRights.removeAll(ATSpecialFunctions.CHAT_DOUBLES);
      this.allRights.addAll(this.mModifiedAuthorizations.specialFunctions.getAllRights());
    }
    if (this.mModifiedAuthorizations.eidAccess != null)
    {
      this.allRights.removeAll(ATEidAccess.CHAT_DOUBLES);
      this.allRights.addAll(this.mModifiedAuthorizations.eidAccess.getAllRights());
    }
    if (this.mModifiedAuthorizations.specificAttributes != null)
    {
      this.allRights.removeAll(ATSpecificAttributes.CHAT_DOUBLES);
      this.allRights.addAll(this.mModifiedAuthorizations.specificAttributes.getAllRights());
    }

    Boolean useCaVer3 = null;
    if (this.allRights.contains(CVCPermission.AUT_SF_PSA) || this.allRights.contains(CVCPermission.AUT_PSA))
    {
      useCaVer3 = Boolean.TRUE;
    }

    LOG.debug(logPrefix + LOG_PRE_AUTH + "Create EAC2InputType");
    EAC2InputTypeWrapper eac2InputType = null;
    try
    {
      eac2InputType = eacServer.executeStep(EACServer.STEP_PACE_OUTPUT_TO_TACA_INPUT,
                                            EAC1OutputTypeWrapper.class,
                                            eac1OutputType,
                                            EAC2InputTypeWrapper.class,
                                            new Object[]{eac1Input, cakProvider, useCaVer3});
    }
    catch (InvalidEidException e)
    {
      // should not be thrown in this step, if this ever is reached we do have a problem
      return handleError(ResultMinor.COMMON_INTERNAL_ERROR, e.getMessage());
    }

    // If the cakProvider for some reason does not provide a certificate chain for the CVC
    // the eacServer returns 'null' from
    if (eac2InputType == null)
    {
      String resultMessage = "Card not valid:"
                             + " Term holder not available or no root found for searched issuer in CVC";
      LOG.debug(logPrefix + LOG_PRE_AUTH + "Card not valid for CVC");
      LOG.debug(logPrefix + LOG_PRE_AUTH
                + "Maybe the EID Server fail to handle ECardIDServerI#addCVCCert(...)"
                + " or card is expired");
      eidInfoContainer.setStatus(EIDStatus.NOT_AUTHENTIC);
      return handleError(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED, resultMessage);
    }

    DIDAuthenticate dIDAuthenticate = factory.createDIDAuthenticate();
    dIDAuthenticate.setAuthenticationProtocolData(eac2InputType);
    dIDAuthenticate.setConnectionHandle(mConnectionHandle);
    dIDAuthenticate.setDIDName(mDIDName);

    returnObject = dIDAuthenticate;
    LOG.debug(logPrefix + "  Response > Create DIDAuthenticate (EAC2)");
    return returnObject;
  }

  private Object handleAuthenticationProtocolData(EAC2OutputTypeWrapper eac2OutputType) throws ECardException
  {
    byte[] efCardSecurity = eac2OutputType.getEFCardSecurity();
    if (efCardSecurity == null)
    {
      throw new ECardException(ResultMinor.COMMON_INCORRECT_PARAMETER, "EF.CardSecurity missing");
    }
    try
    {
      // Set the controller for the process to be able to handle defect list
      setInstanceController(efCardSecurity);

      // Check defects on card before asking for password
      // If the signer certificate was revoked
      if (controller.isCardAffectedBy(DefectType.ID_CERT_REVOKED))
      {
        eidInfoContainer.setStatus(EIDStatus.NOT_AUTHENTIC);
        return handleError(controller.getDefectResult(DefectType.ID_CERT_REVOKED));
      }
      // Private keys could have been compromised
      if (controller.isCardAffectedBy(DefectType.ID_CHIP_AUTH_KEY_REVOKED))
      {
        LOG.warn(logPrefix + LOG_PRE_AUTH + "WARNING: Private keys maybe compromised.\nDefect:\n"
                 + DefectType.ID_CHIP_AUTH_KEY_REVOKED.toStringDetail());
      }
      // Check if data group integrity is not certain;
      if (controller.isCardAffectedBy(DefectType.ID_EID_INTEGRITY))
      {
        return handleError(controller.getDefectResult(DefectType.ID_EID_INTEGRITY));
      }
      // Only a single authentication allowed. Managed by mCard
      if (controller.isCardAffectedBy(DefectType.ID_POWER_DOWN_REQ))
      {
        LOG.debug(logPrefix + LOG_PRE_AUTH + "Expected Defect: " + DefectType.ID_POWER_DOWN_REQ);
      }
      result = eacServer.executeStep(EACServer.STEP_TACA_RESULT,
                                     EAC2OutputTypeWrapper.class,
                                     eac2OutputType,
                                     EACFinal.class,
                                     new Object[]{signedDataChecker});
      if (result == null)
      {
        LOG.debug(logPrefix + "Can not proceed with transmit: result from card not verified");
        eidInfoContainer.setStatus(EIDStatus.NOT_AUTHENTIC);
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                                 "Data in EAC2OutputType could not be verified");
      }
    }
    catch (IllegalArgumentException e)
    {
      LOG.debug(logPrefix + "Illegal argument: " + e.getMessage());
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, e);
    }
    catch (InvalidEidException e)
    {
      LOG.debug(logPrefix + "Card is not on MasterList...abort process");
      eidInfoContainer.setStatus(EIDStatus.NOT_AUTHENTIC);
      throw new ECardException(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED, e.getMessage(), e);
    }
    // probably deprecated
    catch (RuntimeException e)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Internal Error:: " + e, e);
    }
    catch (IOException e)
    {
      String message = "Controller for DefectList not available";
      LOG.debug(logPrefix + message);
      throw new ECardException(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED, message + ": " + e, e);
    }
    return handleFirstTransmit();
  }

  /**
   * With the EAC2Result we can create an TransmitAPDU that is used for all following transmits
   *
   * @return first transmit after authentication
   * @throws InternalError
   * @throws ECardException
   */
  private Object handleFirstTransmit() throws ECardException
  {
    transmitProcess = new EIDSequenceTransmit(this, this.sessionInput.getCAConnection());
    returnObject = transmitProcess.startTransmit(new ArrayList<>(allRights));
    // Create the first transmit request and send to client
    return returnObject;
  }

  private Object handleTransmit(TransmitResponse response) throws ECardException
  {
    returnObject = transmitProcess.handle(response);
    if (returnObject == null)
    {
      if (transmitProcess.transmitDone())
      {
        returnObject = handleDisconnect();
      }
      else
      {
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Transmit fail to complete");
      }
    }
    return returnObject;
  }

  private Object handleDisconnect()
  {
    Result result = new ObjectFactory().createResult();
    result.setResultMajor(ResultMajor.OK.toString());
    ResponseType rt = factory.createResponseType();
    rt.setResult(result);
    returnObject = factory.createStartPAOSResponse(rt);
    return returnObject;
  }

  private Object handleError(ResultMinor minor, String message)
  {
    ObjectFactory of = new ObjectFactory();

    // For all errors we catch we create an ERROR-Result that we send within the StartPAOSResponse
    Result result = of.createResult();
    result.setResultMajor(ResultMajor.ERROR.toString());
    result.setResultMinor(minor.toString());
    result.setResultMessage(ECardCoreUtil.generateInternationalStringType(message));
    return handleError(result);
  }

  private Object handleError(Result result)
  {
    eidInfoContainer.setResult(result);
    ResponseType rt = factory.createResponseType();
    rt.setResult(result);
    returnObject = factory.createStartPAOSResponse(rt);
    return returnObject;
  }

  public static Object createStartPAOSResponseSchemaValError()
  {
    ObjectFactory of = new ObjectFactory();

    Result result = of.createResult();
    result.setResultMajor(ResultMajor.ERROR.toString());
    result.setResultMinor(ResultMinor.COMMON_INCORRECT_PARAMETER.toString());
    result.setResultMessage(ECardCoreUtil.generateInternationalStringType("Received object not conforming to schema"));

    iso.std.iso_iec._24727.tech.schema.ObjectFactory ofIso = new iso.std.iso_iec._24727.tech.schema.ObjectFactory();
    ResponseType rt = ofIso.createResponseType();
    rt.setResult(result);
    return ofIso.createStartPAOSResponse(rt);
  }

  private Object getEAC1DIDAuthenticate() throws ECardException
  {
    eac1Input = new EAC1InputTypeWrapper();
    eac1Input.setProtocol(EACServer.PROTOCOL_EAC2);

    eac1Input.setRequiredCHAT(mRequiredAuthorizations.chat.getEncoded());
    eac1Input.setOptionalCHAT(mOptionalAuthorizations.chat.getEncoded());

    if (mRequiredAuthorizations.eidAccess != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATEidAccessConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_EID_ACCESS);
      eap.setValue(mRequiredAuthorizations.eidAccess.getValue());
      eac1Input.addRequiredPermission(eap);
    }
    if (mOptionalAuthorizations.eidAccess != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATEidAccessConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_EID_ACCESS);
      eap.setValue(mOptionalAuthorizations.eidAccess.getValue());
      eac1Input.addOptionalPermission(eap);
    }
    if (mRequiredAuthorizations.specialFunctions != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATSpecialConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIAL_FUNCTIONS);
      eap.setValue(mRequiredAuthorizations.specialFunctions.getValue());
      eac1Input.addRequiredPermission(eap);
    }
    if (mOptionalAuthorizations.specialFunctions != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATSpecialConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIAL_FUNCTIONS);
      eap.setValue(mOptionalAuthorizations.specialFunctions.getValue());
      eac1Input.addOptionalPermission(eap);
    }
    if (mRequiredAuthorizations.specificAttributes != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATSpecificAttributesConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIFIC_ATTRIBUTES);
      eap.setValue(mRequiredAuthorizations.specificAttributes.getValue());
      eac1Input.addRequiredPermission(eap);
    }
    if (mOptionalAuthorizations.specificAttributes != null)
    {
      ExtendedAccessPermission eap = new ExtendedAccessPermission();
      eap.setType(ATSpecificAttributesConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIFIC_ATTRIBUTES);
      eap.setValue(mOptionalAuthorizations.specificAttributes.getValue());
      eac1Input.addOptionalPermission(eap);
    }

    eac1Input.setCertificateDescription(mCardVerifiableCert.getCVCDescription().getEncoded());
    eac1Input.setAuthenticatedAuxiliaryData(authenticatedAuxiliaryData.getEncoded());

    for ( TerminalData linkCVC : cvcList )
    {
      eac1Input.addCertificate(linkCVC.getEncoded());
    }

    // terminal certificate
    eac1Input.addCertificate(mCardVerifiableCert.getEncoded());

    eac1Input.setTransactionInfo(this.sessionInput.getTransactionInfo());
    DIDAuthenticate dIDAuthenticate = factory.createDIDAuthenticate();
    dIDAuthenticate.setConnectionHandle(mConnectionHandle);
    dIDAuthenticate.setDIDName(mDIDName);
    dIDAuthenticate.setAuthenticationProtocolData(eac1Input);
    return dIDAuthenticate;
  }

  @Override
  public String toString()
  {
    StringBuilder stringBuilder = new StringBuilder("EID SEQUENCE STATUS:\n");
    stringBuilder.append(" Required CHAT      : ").append(mRequiredAuthorizations.chat).append("\n");

    stringBuilder.append(" Optional CHAT      : ").append(mOptionalAuthorizations.chat).append("\n");
    if (mModifiedAuthorizations.chat != null)
    {
      stringBuilder.append(" Modified CHAT       : ").append(mModifiedAuthorizations.chat).append("\n");
    }
    stringBuilder.append(" CardVerifiableCert : ").append(mCardVerifiableCert).append("\n");
    stringBuilder.append(" IFDName            : ").append(mIFDName).append("\n");
    stringBuilder.append(" DIDName            : ").append(mDIDName).append("\n");
    stringBuilder.append(" ConnectionHandle   : ").append(mConnectionHandle).append("\n");
    stringBuilder.append(" Active session     : ").append(this.sessionInput.getSessionID() + "\n");
    stringBuilder.append(" Is started         : ").append(isStarted() + "\n");
    stringBuilder.append(" Is finished        : ").append(isFinished() + "\n");
    if (transmitProcess == null)
    {
      stringBuilder.append(" Transmit done      : ").append("not started\n");
    }
    else
    {
      stringBuilder.append(" Transmit done      : ").append(transmitProcess.transmitDone() + "\n");
    }
    return stringBuilder.toString();
  }

  public String getLogPrefix()
  {
    return logPrefix;
  }

  /**
   * Create an optional {@link CertificateHolderAuthorizationTemplate} by extracting the informations from
   * outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link CertificateHolderAuthorizationTemplate} with optional fields
   * @throws ChatOptionNotAllowedException
   */
  private static CertificateHolderAuthorizationTemplate createOptionalCHAT(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createCHAT(sessionInput, true);
  }

  /**
   * Create the required {@link CertificateHolderAuthorizationTemplate} by extracting the informations from
   * outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link CertificateHolderAuthorizationTemplate} with required fields
   * @throws ChatOptionNotAllowedException
   */
  private static CertificateHolderAuthorizationTemplate createRequiredCHAT(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createCHAT(sessionInput, false);
  }

  private static CertificateHolderAuthorizationTemplate createCHAT(SessionInput input, boolean optionalFields)
    throws ChatOptionNotAllowedException
  {
    // Set the fields from the session input
    Set<EIDKeys> fields;
    if (optionalFields)
    {
      fields = input.getOptionalFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Optional fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    else
    {
      fields = input.getRequiredFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Required fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    Set<CVCPermission> options = CVCPermission.getOptions(fields);

    // permissions in certificate extensions take precedence
    if (input.getTerminalCertificate().getATSpecialFunctions() != null)
    {
      options.removeAll(ATSpecialFunctions.CHAT_DOUBLES);
    }
    if (input.getTerminalCertificate().getATEidAccess() != null)
    {
      options.removeAll(ATEidAccess.CHAT_DOUBLES);
    }

    CertificateHolderAuthorizationTemplate chat = null;
    try
    {
      chat = new CertificateHolderAuthorizationTemplate(ChatTerminalType.AUTHENTICATION_TERMINAL, options);
    }
    catch (IOException | UnsupportedOperationException | IllegalArgumentException e)
    {
      throw new ChatOptionNotAllowedException("Cannot construct CHAT with selected options");
    }
    LOG.debug(input.getLogPrefix() + "CHAT created:\n" + chat);

    // Get the CHAT from the CVC
    CertificateHolderAuthorizationTemplate cvcChat = input.getTerminalCertificate().getCHAT();
    for ( CVCPermission chatOption : chat.getAllRights() )
    {
      if (!cvcChat.areBitsSet(chatOption))
      {
        String message = "Chat option not allowed: " + chatOption;
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
    }
    return chat;
  }

  /**
   * Create an optional {@link ATSpecialFunctions} by extracting the informations from outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link ATSpecialFunctions} with optional fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATSpecialFunctions createOptionalSF(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createSpecialFunctions(sessionInput, true);
  }

  /**
   * Create the required {@link ATSpecialFunctions} by extracting the informations from outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link ATSpecialFunctions} with required fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATSpecialFunctions createRequiredSF(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createSpecialFunctions(sessionInput, false);
  }

  private static ATSpecialFunctions createSpecialFunctions(SessionInput input, boolean optionalFields)
    throws ChatOptionNotAllowedException
  {
    // Set the fields from the session input
    Set<EIDKeys> fields;
    if (optionalFields)
    {
      fields = input.getOptionalFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Optional fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    else
    {
      fields = input.getRequiredFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Required fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    Set<CVCPermission> options = CVCPermission.getOptions(fields);

    ATSpecialFunctions sf;
    try
    {
      sf = ATSpecialFunctions.constructFromCVCPermissions(options);
    }
    catch (IOException e)
    {
      throw new ChatOptionNotAllowedException("Cannot construct ATSpecialFunctions with selected options");
    }
    LOG.debug(input.getLogPrefix() + "ATSpecialFunctions created:\n" + sf);

    // Get the ATSpecialFunctions from the CVC
    ATSpecialFunctions cvcSf = input.getTerminalCertificate().getATSpecialFunctions();
    if (cvcSf == null)
    {
      if (!ATSpecialFunctions.SF_DOUBLES.containsAll(sf.getAllRights()))
      {
        String message = "Complete special functions not allowed";
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
      return null;
    }

    for ( CVCPermission chatOption : sf.getAllRights() )
    {
      if (!cvcSf.existsRight(chatOption.getAccessRightEnum()))
      {
        String message = "Special function not allowed: " + chatOption;
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
    }
    return sf;
  }

  /**
   * Create an optional {@link ATEidAccess} by extracting the informations from outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link ATEidAccess} with optional fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATEidAccess createOptionalATeID(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createEidAccess(sessionInput, true);
  }

  /**
   * Create the required {@link ATEidAccess} by extracting the informations from outer session input
   *
   * @param sessionInput to be used for creation
   * @return {@link ATEidAccess} with required fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATEidAccess createRequiredATeID(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createEidAccess(sessionInput, false);
  }

  private static ATEidAccess createEidAccess(SessionInput input, boolean optionalFields)
    throws ChatOptionNotAllowedException
  {
    // Set the fields from the session input
    Set<EIDKeys> fields;
    if (optionalFields)
    {
      fields = input.getOptionalFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Optional fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    else
    {
      fields = input.getRequiredFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Required fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    Set<CVCPermission> options = CVCPermission.getOptions(fields);

    ATEidAccess eidAccess;
    try
    {
      eidAccess = ATEidAccess.constructFromCVCPermissions(options, input.getPscAccessRightSet());
    }
    catch (IOException e)
    {
      throw new ChatOptionNotAllowedException("Cannot construct ATEidAccess with selected options");
    }
    LOG.debug(input.getLogPrefix() + "ATEidAccessFunctions created:\n" + eidAccess);

    // Get the ATEidAccess from the CVC
    ATEidAccess cvcEidAccess = input.getTerminalCertificate().getATEidAccess();
    if (cvcEidAccess == null)
    {
      if (!ATEidAccess.EID_DOUBLES.containsAll(eidAccess.getAllRights()))
      {
        String message = "Complete eID access not allowed";
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
      return null;
    }

    for ( CVCPermission chatOption : eidAccess.getAllRights() )
    {
      if (!cvcEidAccess.existsRight(chatOption.getAccessRightEnum()))
      {
        String message = "eID access not allowed: " + chatOption;
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
    }
    return eidAccess;
  }

  /**
   * Create an optional {@link ATSpecificAttributes} by extracting the informations from outer session input.
   *
   * @param sessionInput to be used for creation
   * @return {@link ATSpecificAttributes} with optional fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATSpecificAttributes createOptionalSpecificAttributes(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createSpecificAttributes(sessionInput, true);
  }

  /**
   * Create the required {@link ATSpecificAttributes} by extracting the informations from outer session input.
   *
   * @param sessionInput to be used for creation
   * @return {@link ATSpecificAttributes} with required fields
   * @throws ChatOptionNotAllowedException
   */
  private static ATSpecificAttributes createRequiredSpecificAttributes(SessionInput sessionInput)
    throws ChatOptionNotAllowedException
  {
    return createSpecificAttributes(sessionInput, false);
  }

  private static ATSpecificAttributes createSpecificAttributes(SessionInput input, boolean optionalFields)
    throws ChatOptionNotAllowedException
  {
    // Set the fields from the session input
    Set<EIDKeys> fields;
    if (optionalFields)
    {
      fields = input.getOptionalFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Optional fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    else
    {
      fields = input.getRequiredFields();
      LOG.debug(input.getLogPrefix() + LOG_PRE + "Required fields(" + fields.size()
                + ") received from server session input:\n" + fields);
    }
    Set<CVCPermission> options = CVCPermission.getOptions(fields);

    ATSpecificAttributes specAttr;
    try
    {
      specAttr = ATSpecificAttributes.constructFromCVCPermissions(options,
                                                                  input.isPscIncludeSpecific(),
                                                                  input.isAccessAllSpecificAttributes());
    }
    catch (IOException e)
    {
      throw new ChatOptionNotAllowedException("Cannot construct ATSpecificAttributes with selected options");
    }
    LOG.debug(input.getLogPrefix() + "ATSpecificAttributes created:\n" + specAttr);

    // Get the ATSpecificAttributes from the CVC
    ATSpecificAttributes cvcSpecAttr = input.getTerminalCertificate().getATSpecificAttributes();
    if (cvcSpecAttr == null)
    {
      if (!ATSpecificAttributes.SPEC_DOUBLES.containsAll(specAttr.getAllRights()))
      {
        String message = "Complete specific attributes not allowed";
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
      return null;
    }

    for ( CVCPermission chatOption : specAttr.getAllRights() )
    {
      if (!cvcSpecAttr.existsRight(chatOption.getAccessRightEnum()))
      {
        String message = "Specific attribute not allowed: " + chatOption;
        LOG.error(input.getLogPrefix() + message);
        throw new ChatOptionNotAllowedException(message);
      }
    }
    return specAttr;
  }


  public static class Authorizations
  {

    private CertificateHolderAuthorizationTemplate chat = null;

    private ATEidAccess eidAccess = null;

    private ATSpecialFunctions specialFunctions = null;

    private ATSpecificAttributes specificAttributes = null;


    public Authorizations()
    {
      super();
    }

    public Authorizations(CertificateHolderAuthorizationTemplate chat,
                          ATEidAccess eidAccess,
                          ATSpecialFunctions specialFunctions,
                          ATSpecificAttributes specificAttributes)
    {
      super();
      this.chat = chat;
      this.eidAccess = eidAccess;
      this.specialFunctions = specialFunctions;
      this.setSpecificAttributes(specificAttributes);
    }

    public CertificateHolderAuthorizationTemplate getChat()
    {
      return this.chat;
    }

    public void setChat(CertificateHolderAuthorizationTemplate chat)
    {
      this.chat = chat;
    }

    public ATEidAccess getEidAccess()
    {
      return this.eidAccess;
    }

    public void setEidAccess(ATEidAccess eidAccess)
    {
      this.eidAccess = eidAccess;
    }

    public ATSpecialFunctions getSpecialFunctions()
    {
      return this.specialFunctions;
    }

    public void setSpecialFunctions(ATSpecialFunctions specialFunctions)
    {
      this.specialFunctions = specialFunctions;
    }

    public ATSpecificAttributes getSpecificAttributes()
    {
      return this.specificAttributes;
    }

    public void setSpecificAttributes(ATSpecificAttributes specificAttributes)
    {
      this.specificAttributes = specificAttributes;
    }
  }
}
