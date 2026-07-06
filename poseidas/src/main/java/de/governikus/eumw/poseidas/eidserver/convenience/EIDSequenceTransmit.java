/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1TaggedObject;

import de.governikus.autent.asn1.si.RestrictedIdentificationInfo;
import de.governikus.autent.asn1.si.SecurityInfos;
import de.governikus.autent.asn1.utils.PublicKeyUtils;
import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessagingException;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;
import de.governikus.eumw.poseidas.cardbase.npa.NPAUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.batch.Batch;
import de.governikus.eumw.poseidas.cardserver.eac.functions.batch.BatchParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.FileParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.Read;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectApplication;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectFile;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerificationParameter;
import de.governikus.eumw.poseidas.ecardcore.core.ECardException;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import de.governikus.panstar.sdk.utils.constant.EIDAttributeName;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;
import lombok.extern.slf4j.Slf4j;


/**
 * Perform the communication with the eID card after the EAC protocol has finished, i.e. read fields and run functions.
 */
@Slf4j
public class EIDSequenceTransmit
{

  /**
   * LOGGER for this class. Note: Data should be logged only for LEVEL.TRACE
   */
  private static final String LOG_SELECT = "[Transmit select] ";

  private static final String LOG_COMMAND = "[Transmit command] ";

  private static final String LOG_DATA = "[Transmit data]";

  /**
   * Sequence which reached the transmit process
   */
  private final EIDSequence parent;

  /**
   * Root transmit to create mCard objects
   */
  private final TransmitAPDU transmit;

  /**
   * Slot for card in use
   */
  private final byte[] slotHandle;

  /**
   * Batch for transmit collections
   */
  private final Batch transmitBatch;

  /**
   * Select application
   */
  private final SelectApplication select;

  /**
   * Select the file to be read
   */
  private final SelectFile selectFile;

  /**
   * Read command on selected file
   */
  private final Read readFile;

  /**
   * Command for age verification
   */
  private AgeVerification ageVerification;

  /**
   * Command for restricted and blocking identification
   */
  private RestrictedIdentification restrictedIdentification;

  /**
   * Command for the community ID
   */
  private CommunityIDVerification communityIDVerification;

  /**
   * Command for document validity
   */
  private DocumentValidityVerification documentValidityVerification;

  /**
   * Fields allowed to be read selected by the user on client side. Note: it is imperative that the field "install
   * qualified certificate" is on last position in the list, if present.
   */
  private List<EIDAttributeName> fields;

  /**
   * List of verification commands to be done on card. List provides correct sort of verifications in process
   */
  private List<VerificationCommand> verifications;

  /**
   * State of transmit process
   */
  private SequenceState state;

  public enum SequenceState
  {
    BATCH_COMMANDS, BATCH_DATA, TRANSMIT_DONE,
  }

  private enum VerificationCommand
  {
    DOCUMENT_VALIDITY,
    AGE_VERIFICATION,
    RESTRICTED_IDENTIFICATION,
    BLOCKING_IDENTIFICATION,
    MUNICIPALITY_ID_VERIFICATION
  }

  /**
   * Instance to handle all transmits for a EIDSequence
   *
   * @param sequence
   */
  EIDSequenceTransmit(EIDSequence sequence)
  {
    parent = sequence;
    ConnectionHandleType connectionHandle = parent.getConnectionHandle();
    byte[] slotHandleFromConnectionHandle = connectionHandle.getSlotHandle();
    slotHandle = slotHandleFromConnectionHandle == null ? new byte[]{0} : slotHandleFromConnectionHandle;
    transmit = new TransmitAPDU(parent.getEACFinal().getSM());

    // Create all objects required for transmit commands
    select = new SelectApplication(transmit);
    selectFile = new SelectFile(transmit);
    readFile = new Read(transmit);
    transmitBatch = new Batch(transmit);
  }

  /**
   * Checks if transmit is finished
   *
   * @return true if all transmits are done
   */
  boolean transmitDone()
  {
    return SequenceState.TRANSMIT_DONE.equals(state);
  }

  /**
   * Starts the transmit process
   *
   * @param allRights from modified chat
   * @return the first transmit which depends on the state of this instance
   * @throws ECardException
   */
  Object startTransmit(List<EIDAttributeName> allRights) throws ECardException
  {
    // If state was not set externally get the default
    if (state == null)
    {
      state = SequenceState.BATCH_COMMANDS;
    }
    setVerificationStates(allRights);
    return getTransmitRequest();
  }

  /**
   * Handles a response from client, handles the content and returns the next request
   *
   * @param response to be read
   * @return Next request to be sent to the client
   * @throws ECardException
   */
  public Object handle(TransmitResponse response) throws ECardException
  {
    TransmitAPDUResult transmitResult = new TransmitAPDUResult(response);
    log.debug("{} [Transmit] Handle response: {}", parent.getLogPrefix(), state.name());
    // Handle the converted result from eCard by result step to be able to handle mCard batch
    transmitResult = transmitBatch.resultStep(transmitResult.getData());
    if (transmitResult.getThrowable() instanceof SecureMessagingException)
    {
      parent.getEIDInfoContainer().setStatus(EIDStatus.NOT_AUTHENTIC);
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, transmitResult.getThrowable());
    }
    else if (transmitResult.getThrowable() != null)
    {
      log.warn("Got unexpected exception: {}", transmitResult.getThrowable());
    }

    switch (state)
    {
      case BATCH_COMMANDS:
        return handleBatchCommands(transmitResult);
      case BATCH_DATA:
        return handleBatchData(transmitResult);
      case TRANSMIT_DONE:
        return null;
      default:
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Unknown transmit state");
    }
  }

  private Object getBatchCommands() throws ECardException
  {
    // Collect all commands here, so mCard can handle internal encrypt/decrypt counter
    List<InputAPDUInfoType> listBatches = new ArrayList<>();

    // Always select application to be able to handle commands on card
    listBatches.addAll(select.create(getFileParameterSelectApplication()));

    // Add all commands to be done
    for ( VerificationCommand verification : verifications )
    {
      switch (verification)
      {
        case AGE_VERIFICATION:
          listBatches.addAll(getCommandAgeVerification());
          break;
        case BLOCKING_IDENTIFICATION:
          listBatches.addAll(getCommandBlockingIdentification());
          break;
        case MUNICIPALITY_ID_VERIFICATION:
          listBatches.addAll(getCommandCommunityIdentification());
          break;
        case DOCUMENT_VALIDITY:
          listBatches.addAll(getCommandDocumentValidity());
          break;
        case RESTRICTED_IDENTIFICATION:
          listBatches.addAll(getCommandRestrictedIdentification());
          break;
        default:
      }
    }

    BatchParameter batchParameters = new BatchParameter(listBatches);
    return transmitBatch.parameterStep(batchParameters, slotHandle);
  }

  private Object getBatchData() throws ECardException
  {
    // Batch list to be filled
    List<InputAPDUInfoType> batchList = new ArrayList<>();

    StringBuilder tempInfo = new StringBuilder("FIELDS:\n");
    for ( EIDAttributeName field : fields )
    {
      tempInfo.append(" o " + field.name());
    }
    log.debug("{}{}{}", parent.getLogPrefix(), LOG_DATA, tempInfo.toString());

    for ( EIDAttributeName field : fields )
    {
      if (field != null)
      {
        switch (field)
        {
          // These fields should not be read again because they were checked by verification and will not
          // return
          // a data result
          case AgeVerification:
          case PlaceVerification:
          case RestrictedID:
            continue;
          default:
        }

        // do not read fields with generic attributes here
        if (field.getSfi() != null && field.getSfi() < 0x17)
        {
          ReadParameter readParameter = new ReadParameter(0, 65536, field.getSfi());
          log.debug("{}{}Create read for {}", parent.getLogPrefix(), LOG_DATA, field.name());
          batchList.addAll(readFile.create(readParameter));
        }
        // do not read fields with generic attributes here
        else if (field.getFid() != null && new BigInteger(field.getFid()).intValue() < 0x0117)
        {
          FileParameter file = new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID), field.getFid(), true);
          log.debug("{}{}Create select for {}", parent.getLogPrefix(), LOG_DATA, field.name());
          batchList.addAll(selectFile.create(file));
          log.debug("{}{}Create read for this field", parent.getLogPrefix(), LOG_DATA);
          batchList.addAll(readFile.create(null));
        }
        else
        {
          log.debug("{}{}Unknown handle on: {}", parent.getLogPrefix(), LOG_DATA, field.name());
        }
      }
      else
      {
        log.debug("{}{}Empty field", parent.getLogPrefix(), LOG_DATA);
      }
    }

    if (batchList.isEmpty())
    {
      log.debug("{}{}No data field to be read", parent.getLogPrefix(), LOG_DATA);
      state = SequenceState.TRANSMIT_DONE;
      return getTransmitRequest();
    }
    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private List<InputAPDUInfoType> getCommandAgeVerification()
  {
    if (ageVerification == null)
    {
      ageVerification = new AgeVerification(transmit);
    }
    return ageVerification.create(new AgeVerificationParameter());
  }

  private List<InputAPDUInfoType> getCommandBlockingIdentification() throws ECardException
  {
    return getCommandRestrictedIdentification(false);
  }

  private List<InputAPDUInfoType> getCommandCommunityIdentification()
  {
    if (communityIDVerification == null)
    {
      communityIDVerification = new CommunityIDVerification(transmit);
    }
    return communityIDVerification.create(new CommunityIDVerificationParameter());
  }

  private List<InputAPDUInfoType> getCommandDocumentValidity()
  {
    if (documentValidityVerification == null)
    {
      documentValidityVerification = new DocumentValidityVerification(transmit);
    }
    return documentValidityVerification.create(new DocumentValidityVerificationParameter());
  }

  private List<InputAPDUInfoType> getCommandRestrictedIdentification() throws ECardException
  {
    return getCommandRestrictedIdentification(true);
  }

  private List<InputAPDUInfoType> getCommandRestrictedIdentification(boolean ri) throws ECardException
  {
    try
    {
      RestrictedIdentificationParameter parameter = getParameterRestrictedIdentification(ri);
      if (restrictedIdentification == null)
      {
        restrictedIdentification = new RestrictedIdentification(transmit);
      }
      return restrictedIdentification.create(parameter);
    }
    catch (Exception e)
    {
      throw new ECardException(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED,
                               "Unable to create command for blocking identification", e);
    }
  }

  private FileParameter getFileParameterSelectApplication()
  {
    return new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID),
                             Hex.parse(EIDConstants.EID_FID_DG01_DOCUMENT_TYPE), true);
  }

  private RestrictedIdentificationParameter getParameterRestrictedIdentification(boolean ri) throws IOException
  {
    ASN1TaggedObject keyTaggedObject = ASN1TaggedObject.getInstance(parent.getCVC().getRIKey1());
    SecurityInfos cardSecurity = NPAUtil.fromCardSecurityBytes(parent.getEACFinal().getCardSecurityBytes());
    List<RestrictedIdentificationInfo> infos = cardSecurity.getRestrictedIdentificationInfoList();
    for ( RestrictedIdentificationInfo info : infos )
    {
      if (info.isAuthorizedOnly() == ri)
      {
        return new RestrictedIdentificationParameter(info, PublicKeyUtils.getPublicKeyWithoutTag(keyTaggedObject),
                                                     null);
      }
    }
    throw new IOException("no matching RestrictedIdentificationInfo found");
  }

  private Object getTransmitRequest() throws ECardException
  {
    log.debug("{}[Transmit] Get next transmit: {}", parent.getLogPrefix(), state.name());
    switch (state)
    {
      case BATCH_COMMANDS:
        return getBatchCommands();
      case BATCH_DATA:
        return getBatchData();
      case TRANSMIT_DONE:
        return null;
      default:
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Unknown transmit state");
    }
  }


  private Object handleBatchCommands(TransmitAPDUResult transmitResult) throws ECardException
  {
    int position = 0;
    // Check if select application was successful
    SelectResult selected = select.evaluate(transmitResult, new int[]{position++});
    if (!selected.isSelected())
    {
      throw new ECardException(ResultMinor.SAL_FILE_NOT_FOUND, "Select application failed");
    }

    log.debug("{}{}Select application successful", parent.getLogPrefix(), LOG_SELECT);
    for ( VerificationCommand verification : verifications )
    {
      log.debug("{}{}Command checked: {} at position {}",
                parent.getLogPrefix(),
                LOG_COMMAND,
                verification.name(),
                position);
      switch (verification)
      {
        case AGE_VERIFICATION:
          handleBatchCommandAgeVerification(transmitResult, position++);
          break;
        case BLOCKING_IDENTIFICATION:
          // Restricted identifications return two result. First is only that result is OK
          log.debug("{}{}Start: {}", parent.getLogPrefix(), LOG_COMMAND, verification.name());
          // Check select blocking identification was successful
          checkSWCode(transmitResult, position++);
          handleBatchCommandBlockingIdentification(transmitResult, position++);
          if (parent.getEIDInfoContainer().getStatus() == EIDStatus.REVOKED)
          {
            state = SequenceState.TRANSMIT_DONE;
            return getTransmitRequest();
          }
          break;
        case MUNICIPALITY_ID_VERIFICATION:
          handleBatchCommandCommunityIdentification(transmitResult, position++);
          break;
        case DOCUMENT_VALIDITY:
          handleBatchCommandDocumentValidity(transmitResult, position++);
          if (parent.getEIDInfoContainer().getStatus() == EIDStatus.EXPIRED)
          {
            state = SequenceState.TRANSMIT_DONE;
            return getTransmitRequest();
          }
          break;
        case RESTRICTED_IDENTIFICATION:
          // Restricted identifications return two result. First is only that result is OK
          checkSWCode(transmitResult, position++);
          handleBatchCommandRestrictedIdentification(transmitResult, position++);
          break;
        default:
      }
      log.debug("{}{}NEXT >>> ", parent.getLogPrefix(), LOG_COMMAND);
    }
    state = SequenceState.BATCH_DATA;
    return getTransmitRequest();
  }

  private static void checkSWCode(TransmitAPDUResult transmitResult, int additionalResults) throws ECardException
  {
    ResponseAPDU r = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(additionalResults));
    if (r.getSW() != SmartCardCodeConstants.SUCCESSFULLY_PROCESSED)
    {
      throw new ECardException(ResultMinor.SAL_FILE_NOT_FOUND,
                               "Selecting card application failed. TransmitResult contains no success code but "
                                                               + r.getSW());
    }
  }

  private void handleBatchCommandAgeVerification(TransmitAPDUResult transmitResult, int index) throws ECardException
  {
    ValidityVerificationResult result = ageVerification.evaluate(transmitResult, new int[]{index});
    checkAgeVerification(result);
  }

  private void handleBatchCommandBlockingIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    log.debug("{}{}Evaluate RI with MCard", parent.getLogPrefix(), LOG_COMMAND);
    RestrictedIdentificationResult result = restrictedIdentification.evaluate(transmitResult, new int[]{index});
    log.debug("{}{}Result from MCard: {}", parent.getLogPrefix(), LOG_COMMAND, result);
    checkBlockingIdentification(result);
    log.debug("{}{}check BlockingIdentification done", parent.getLogPrefix(), LOG_COMMAND);
  }

  private void handleBatchCommandCommunityIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    ValidityVerificationResult result = communityIDVerification.evaluate(transmitResult, new int[]{index});
    checkCommunityIdentification(result);
  }


  private void handleBatchCommandDocumentValidity(TransmitAPDUResult transmitResult, int index) throws ECardException
  {
    ValidityVerificationResult result = documentValidityVerification.evaluate(transmitResult, new int[]{index});
    checkDocumentValidity(result);
  }

  private void handleBatchCommandRestrictedIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    RestrictedIdentificationResult result = restrictedIdentification.evaluate(transmitResult, new int[]{index});
    checkRestrictedIdentification(result);
  }

  private Object handleBatchData(TransmitAPDUResult transmitResult) throws ECardException
  {
    int position = 0;

    for ( EIDAttributeName field : fields )
    {
      if ((field.getFid() == null || new BigInteger(field.getFid()).intValue() >= 0x0117)
          && (field.getSfi() == null || field.getSfi() >= 0x17))
      {
        // there is nothing we can read
        continue;
      }
      log.debug("{}READ field{}", parent.getLogPrefix(), field.name());

      SelectResult file = null;
      boolean withoutSelect = false;
      if (field.getSfi() == null)
      {
        file = selectFile.evaluate(transmitResult, new int[]{position++});
      }
      else
      {
        withoutSelect = true;
      }

      if (withoutSelect || file.isSelected())
      {
        ReadResult result = readFile.evaluate(transmitResult, new int[]{position++});
        if (result.getThrowable() != null)
        {
          if (result.getThrowable() instanceof FileNotFoundException)
          {
            setParentPut(field, new EIDInfoResultNotOnChip());
          }
          else
          {
            log.warn("Other exception as FileNotFoundException was thrown: {}", result.getThrowable());
          }
          log.debug("{}{}Could not read file for {}", parent.getLogPrefix(), LOG_DATA, field.name());
        }
        else if (!ArrayUtil.isNullOrEmpty(result.getFileContent()) && result.getFileContent()[0] != 0x00)
        {
          EIDInfoResult value = ASN1Parser.getASN1Value(result, field, parent);
          log.debug("{}{}{} added to eidInfoContainer.", parent.getLogPrefix(), LOG_DATA, field.name());
          setParentPut(field, value);
        }
        else
        {
          log.debug("{}{}No result (read) for file {}", parent.getLogPrefix(), LOG_DATA, field.name());
        }
      }
      else
      {
        setParentPut(field, new EIDInfoResultNotOnChip());
        log.debug("{}{}Could not select file for {}", parent.getLogPrefix(), LOG_DATA, field.name());
      }
    }
    state = SequenceState.TRANSMIT_DONE;
    return getTransmitRequest();
  }

  private void checkAgeVerification(ValidityVerificationResult result) throws ECardException
  {
    if (result.getThrowable() == null)
    {
      setParentPut(EIDAttributeName.AgeVerification, new EIDInfoResultVerification(result.getData()));
    }
    else
    {
      throw new ECardException(ResultMinor.SAL_MEAC_AGE_VERIFICATION_FAILED_WARNING,
                               "The age verification process fails: " + result.getThrowable(), result.getThrowable());
    }
  }

  private void checkBlockingIdentification(byte[] id) throws ECardException
  {
    BlackListConnector connector = parent.getConnector();
    log.debug("{}{}Got Blacklist connector", parent.getLogPrefix(), LOG_COMMAND);
    if (connector == null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "No Blacklist connector available");
    }

    log.debug("{}{}Try check...", parent.getLogPrefix(), LOG_COMMAND);

    boolean documentValidityVerificationFailed = connector.contains(id);
    log.debug("{}{}Check done", parent.getLogPrefix(), LOG_COMMAND);
    if (documentValidityVerificationFailed)
    {
      log.debug("{}{}Found Card on BlackList", parent.getLogPrefix(), LOG_COMMAND);
      setParentClear();
      parent.getEIDInfoContainer().setStatus(EIDStatus.REVOKED);
    }
    else
    {
      log.debug("{}{}Card not found on BlackList", parent.getLogPrefix(), LOG_COMMAND);
    }
    log.debug("{}{}Leave Blacklist connector usage", parent.getLogPrefix(), LOG_COMMAND);
  }

  private void checkBlockingIdentification(RestrictedIdentificationResult result) throws ECardException
  {
    log.debug("{}{}check BlockingIdentification...", parent.getLogPrefix(), LOG_COMMAND);
    if (result.getThrowable() == null && result.getFirstID() != null)
    {
      log.debug("{}{}Result from MCard ok", parent.getLogPrefix(), LOG_COMMAND);
      // Checking card for blacklist
      byte[] currentSectorSpecificID = result.getFirstID();
      log.debug("{}{}First ID OK", parent.getLogPrefix(), LOG_COMMAND);
      this.checkBlockingIdentification(currentSectorSpecificID);
    }
    else
    {
      log.debug("{}{}Exception!!!", parent.getLogPrefix(), LOG_COMMAND);
      if (result.getThrowable() != null)
      {
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                                 "Blocking identification verification failed: " + result.getThrowable());
      }
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Blocking identification verification failed: " + "Result contains no ID to use");
    }
    log.debug("{}{}Leave method", parent.getLogPrefix(), LOG_COMMAND);
  }

  private void checkCommunityIdentification(ValidityVerificationResult result) throws ECardException
  {

    if (result.getThrowable() == null)
    {
      setParentPut(EIDAttributeName.PlaceVerification, new EIDInfoResultVerification(result.getData()));
    }
    else
    {
      throw new ECardException(ResultMinor.SAL_MEAC_COMMUNITY_VERIFICATION_FAILED_WARNING,
                               "Community affiliation process fails: " + result.getThrowable(), result.getThrowable());
    }
  }

  private void checkDocumentValidity(ValidityVerificationResult result) throws ECardException
  {
    if (result.getThrowable() == null)
    {
      Boolean isValid = result.getData();
      if (isValid)
      {
        setParentPut(EIDAttributeName.DocumentValidity, new EIDInfoResultVerification(result.getData()));
        parent.getEIDInfoContainer().setStatus(EIDStatus.VALID);
      }
      else
      {
        log.error("{}[SERVER] Document Validity negative", parent.getLogPrefix());
        log.debug("{}  Response > Create Transmit failed (DocumentValidity): {}",
                  parent.getLogPrefix(),
                  result.getData().toString());
        setParentClear();
        setParentPut(EIDAttributeName.DocumentValidity, new EIDInfoResultVerification(result.getData()));
        parent.getEIDInfoContainer().setStatus(EIDStatus.EXPIRED);
      }
    }
    else
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Document validity failed and throw an exception: " + result.getThrowable());
    }
  }

  private void checkRestrictedIdentification(byte[] id1, byte[] id2)
  {
    EIDInfoResultRestrictedID eIDResult = new EIDInfoResultRestrictedID(id1, id2);
    setParentPut(EIDAttributeName.RestrictedID, eIDResult);
  }

  private void checkRestrictedIdentification(RestrictedIdentificationResult result) throws ECardException
  {
    if (result.getThrowable() == null && result.getFirstID() != null)
    {
      this.checkRestrictedIdentification(result.getFirstID(), result.getSecondID());
    }
    else
    {
      String base = "Restricted identification verification failed: ";
      if (result.getThrowable() != null)
      {
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, base + result.getThrowable(),
                                 result.getThrowable());
      }
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, base + "Result contains no ID to use");
    }
  }

  private void setParentClear()
  {
    parent.getEIDInfoContainer().getInfoMap().clear();
  }

  private void setParentPut(EIDAttributeName key, EIDInfoResult value)
  {
    parent.getEIDInfoContainer().getInfoMap().put(key, value);
  }

  /**
   * Method to set the checks that should be done on card
   */
  private void setVerificationStates(List<EIDAttributeName> fieldList)
  {
    this.fields = fieldList;

    // Initialize the verification list
    verifications = new ArrayList<>();

    // Always check for blacklisted ID
    verifications.add(VerificationCommand.BLOCKING_IDENTIFICATION);
    // Always check for document validity
    verifications.add(VerificationCommand.DOCUMENT_VALIDITY);

    if (this.fields.remove(EIDAttributeName.AgeVerification))
    {
      verifications.add(VerificationCommand.AGE_VERIFICATION);
    }
    if (this.fields.remove(EIDAttributeName.RestrictedID))
    {
      verifications.add(VerificationCommand.RESTRICTED_IDENTIFICATION);
    }
    if (this.fields.remove(EIDAttributeName.PlaceVerification))
    {
      verifications.add(VerificationCommand.MUNICIPALITY_ID_VERIFICATION);
    }

    // Output which checks are done
    StringBuilder debug = new StringBuilder(LOG_COMMAND + "VerificationStates set - Checks to be done: \n");
    verifications.stream().forEach(s -> debug.append("    o " + s.name() + "\n"));
    log.debug("{}{}", parent.getLogPrefix(), debug.toString());
  }
}
