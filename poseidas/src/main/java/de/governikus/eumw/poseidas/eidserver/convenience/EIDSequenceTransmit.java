/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationInfo;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessagingException;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;
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
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
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
  private List<CVCPermission> fields;

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
  Object startTransmit(List<CVCPermission> allRights) throws ECardException
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
   * @return Next request to be send to the client
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
    for ( CVCPermission field : fields )
    {
      tempInfo.append(" o " + field.getDataFieldName());
    }
    log.debug("{}{}{}", parent.getLogPrefix(), LOG_DATA, tempInfo.toString());

    for ( CVCPermission field : fields )
    {
      if (field != null)
      {
        switch (field)
        {
          // These fields should not be read again because they were checked by verification and will not
          // return
          // a data result
          case AUT_AGE_VERIFICATION:
          case AUT_MUNICIPALITY_ID_VERIFICATION:
          case AUT_RESTRICTED_IDENTIFICATION:
            continue;
          default:
        }

        // do not read fields with generic attributes here
        if (field.getSFID() != null && Hex.parse(field.getSFID())[0] < 0x17)
        {
          ReadParameter readParameter = new ReadParameter(0, 65536, Hex.parse(field.getSFID())[0]);
          log.debug("{}{}Create read for {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
          batchList.addAll(readFile.create(readParameter));
        }
        // do not read fields with generic attributes here
        else if (field.getFID() != null && new BigInteger(Hex.parse(field.getFID())).intValue() < 0x0117)
        {
          FileParameter file = new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID), Hex.parse(field.getFID()),
                                                 true);
          log.debug("{}{}Create select for {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
          batchList.addAll(selectFile.create(file));
          log.debug("{}{}Create read for this field", parent.getLogPrefix(), LOG_DATA);
          batchList.addAll(readFile.create(null));
        }
        else
        {
          log.debug("{}{}Unknown handle on: {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
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
    ASN1 keyASN = new ASN1(parent.getCVC().getRIKey1());
    SecurityInfos cardSecurity = NPAUtil.fromCardSecurityBytes(parent.getEACFinal().getCardSecurityBytes());
    List<RestrictedIdentificationInfo> infos = cardSecurity.getRestrictedIdentificationInfo();
    for ( RestrictedIdentificationInfo info : infos )
    {
      if (info.getParams().getAuthorizedOnly() == ri)
      {
        return new RestrictedIdentificationParameter(info, keyASN.getValue(), null);
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


  /**
   * Parses the ASN.1 to get a representable data
   *
   * @param readResult to create an ASN.1
   * @param dataFieldName to be read
   * @return UTF-8 String with the parsed value from ASN.1
   */
  private EIDInfoResult getASN1Value(ReadResult readResult, String dataFieldName)
  {
    StringBuilder result = new StringBuilder();
    try
    {
      ASN1 asn1 = new ASN1(readResult.getFileContent());
      boolean isBirthPlace = dataFieldName.equals(CVCPermission.AUT_READ_DG09.getDataFieldName());
      // If case place of residence or of birth we handle addresses
      if (isBirthPlace || dataFieldName.equals(CVCPermission.AUT_READ_DG17.getDataFieldName()))
      {
        ASN1 addressASN = new ASN1(asn1.getValue());
        if (addressASN.getChildElementCount() < 1)
        {
          throw new IOException("Unexpected address-format: "
                                + new String(addressASN.getValue(), StandardCharsets.UTF_8));
        }
        // This is a a1 tag, but the getTag() functions removes the first bit.
        else if (addressASN.getTag().intValue() == 0x21)
        {
          return new EIDInfoResultPlaceFreeText(new String(new ASN1(addressASN.getValue()).getValue(),
                                                           StandardCharsets.UTF_8));
        }
        // This is a a2 tag, but the getTag() functions removes the first bit.
        else if (addressASN.getTag().intValue() == 0x22)
        {
          return new EIDInfoResultPlaceNo(new String(new ASN1(addressASN.getValue()).getValue(),
                                                     StandardCharsets.UTF_8));
        }
        else if (addressASN.getTag().intValue() == 0x30)
        {
          String street = getASNAdress(addressASN, (byte)0xaa, isBirthPlace);
          String city = getASNAdress(addressASN, (byte)0xab, isBirthPlace);
          String stateAddr = getASNAdress(addressASN, (byte)0xac, isBirthPlace);
          String country = getASNAdress(addressASN, (byte)0xad, isBirthPlace);
          String zipCode = getASNAdress(addressASN, (byte)0xae, isBirthPlace);
          return new EIDInfoResultPlaceStructured(street, city, stateAddr, country, zipCode);
        }
        else
        {
          throw new IOException("Unexpected address-format: "
                                + new String(addressASN.getValue(), StandardCharsets.UTF_8));
        }
      }

      if (dataFieldName.equals(CVCPermission.AUT_READ_DG19.getDataFieldName())
          || dataFieldName.equals(CVCPermission.AUT_READ_DG20.getDataFieldName()))
      {
        ASN1 textASN = new ASN1(asn1.getValue());
        // This is a a1 tag, but the getTag() functions removes the first bit.
        if (textASN.getTag().intValue() == 0x21)
        {
          return new EIDInfoResultString(new String(new ASN1(textASN.getValue()).getValue(), StandardCharsets.UTF_8));
        }
        // This is a a2 tag, but the getTag() functions removes the first bit.
        if (textASN.getTag().intValue() == 0x22)
        {
          byte[] octetString = new ASN1(textASN.getValue()).getValue();
          Inflater inf = new Inflater();
          inf.setInput(octetString);
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          byte[] buf = new byte[256];
          while (!inf.finished())
          {
            int len;
            try
            {
              len = inf.inflate(buf);
            }
            catch (DataFormatException e)
            {
              throw new IOException("Unexpected text format: " + new String(textASN.getValue(), StandardCharsets.UTF_8),
                                    e);
            }
            baos.write(buf, 0, len);
          }
          baos.close();
          inf.end();
          byte[] inflated = baos.toByteArray();
          return new EIDInfoResultPlaceNo(new String(new ASN1(inflated).getValue(), StandardCharsets.UTF_8));
        }
      }
      if (dataFieldName.equals(CVCPermission.AUT_READ_DG12.getDataFieldName()))
      {
        return new EIDInfoResultByteArray(asn1.getValue());
      }
      if (dataFieldName.equals(CVCPermission.AUT_READ_DG14.getDataFieldName())
          || dataFieldName.equals(CVCPermission.AUT_READ_DG18.getDataFieldName()))
      {
        ASN1 octetString = new ASN1(asn1.getValue());
        return new EIDInfoResultByteArray(octetString.getValue());
      }

      ASN1 simpleASN = new ASN1(asn1.getValue());
      String fieldValue = new String(simpleASN.getValue(), StandardCharsets.UTF_8);
      result.append(fieldValue);
      log.debug("{}{}[ASN1 Simple] : {}", parent.getLogPrefix(), LOG_DATA, fieldValue);
      return new EIDInfoResultString(result.toString());
    }
    catch (IOException e)
    {
      log.error("{}{}Can't get FileContent for field: {}", parent.getLogPrefix(), LOG_DATA, dataFieldName, e);
    }
    return null;
  }

  /**
   * Gets from an ASN1 the address informations by tag
   *
   * @param adressASN the ASN1 to parse
   * @param tag of an address
   * @param isBirthPlace check if birth or residence place
   * @return the value as String
   * @throws IOException
   */
  private static String getASNAdress(ASN1 adressASN, byte tag, boolean isBirthPlace) throws IOException
  {
    ASN1[] adressElement = adressASN.getChildElementsByDTagBytes(new byte[]{tag});
    if (adressElement.length < 1)
    {
      if (isBirthPlace || tag == (byte)0xac || tag == (byte)0xaa)
      {
        return null;
      }
      else
      {
        throw new IOException(tag + " tag for address is no optional field and must be filled");
      }
    }
    else
    {
      ASN1 adressElementValue = new ASN1(adressElement[0].getValue());
      return new String(adressElementValue.getValue(), StandardCharsets.UTF_8);
    }
  }

  private Object handleBatchCommands(TransmitAPDUResult transmitResult) throws ECardException
  {
    int additionalResults = 0;
    // Check if select application was successful
    SelectResult selected = select.evaluate(transmitResult, new int[]{additionalResults});
    // Select is the first additional result to count for commands
    additionalResults++;
    if (selected.isSelected())
    {
      log.debug("{}{}Select application successful", parent.getLogPrefix(), LOG_SELECT);

      for ( VerificationCommand verification : verifications )
      {
        log.debug("{}{}Command checked: {} at position {}",
                  parent.getLogPrefix(),
                  LOG_COMMAND,
                  verification.name(),
                  additionalResults);
        switch (verification)
        {
          case AGE_VERIFICATION:
            handleBatchCommandAgeVerification(transmitResult, additionalResults);
            additionalResults++;
            break;
          case BLOCKING_IDENTIFICATION:
            // Restricted identifications return two result. First is only that result is OK
            log.debug("{}{}Start: {}", parent.getLogPrefix(), LOG_COMMAND, verification.name());
            // Check select blocking identification was successful
            checkSWCode(transmitResult, additionalResults);
            additionalResults++;
            handleBatchCommandBlockingIdentification(transmitResult, additionalResults);
            if (parent.getEIDInfoContainer().getStatus() == EIDStatus.REVOKED)
            {
              state = SequenceState.TRANSMIT_DONE;
              return getTransmitRequest();
            }
            additionalResults++;
            break;
          case MUNICIPALITY_ID_VERIFICATION:
            handleBatchCommandCommunityIdentification(transmitResult, additionalResults);
            additionalResults++;
            break;
          case DOCUMENT_VALIDITY:
            handleBatchCommandDocumentValidity(transmitResult, additionalResults);
            if (parent.getEIDInfoContainer().getStatus() == EIDStatus.EXPIRED)
            {
              state = SequenceState.TRANSMIT_DONE;
              return getTransmitRequest();
            }
            additionalResults++;
            break;
          case RESTRICTED_IDENTIFICATION:
            // Restricted identifications return two result. First is only that result is OK
            checkSWCode(transmitResult, additionalResults);
            additionalResults++;
            handleBatchCommandRestrictedIdentification(transmitResult, additionalResults);
            additionalResults++;
            break;
          default:
        }
        log.debug("{}{}NEXT >>> ", parent.getLogPrefix(), LOG_COMMAND);
      }

      for ( CVCPermission field : fields )
      {
        if ((field.getFID() == null || new BigInteger(Hex.parse(field.getFID())).intValue() < 0x0117)
            && (field.getSFID() == null || Hex.parse(field.getSFID())[0] < 0x17))
        {
          // only handle generic attributes here
        }
        else
        {
          log.debug("{}READ field{}", parent.getLogPrefix(), field.getDataFieldName());

          SelectResult file = null;
          boolean withoutSelect = false;
          if (field.getSFID() == null)
          {
            file = selectFile.evaluate(transmitResult, new int[]{additionalResults++});
          }
          else
          {
            withoutSelect = true;
          }

          if (withoutSelect || file.isSelected())
          {
            ReadResult result = readFile.evaluate(transmitResult, new int[]{additionalResults++});
            if (result.getThrowable() != null)
            {
              if (result.getThrowable() instanceof FileNotFoundException)
              {
                setParentPut(EIDKeys.valueOf(field.getDataFieldName()), new EIDInfoResultNotOnChip());
              }
              else
              {
                log.warn("Other exception as FileNotFoundException was thrown: {}", result.getThrowable());
              }
              log.debug("{}{}Could not read file for {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
            }
            else if (ArrayUtil.isNullOrEmpty(result.getFileContent()) || result.getFileContent()[0] == 0x00)
            {
              log.debug("{}{}No result (read) for file {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
            }
            else
            {
              EIDInfoResult value = getASN1Value(result, field.getDataFieldName());
              log.debug("{}{}{} added to eidInfoContainer.", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
              setParentPut(EIDKeys.valueOf(field.getDataFieldName()), value);
            }
          }
        }
      }
    }
    else
    {
      throw new ECardException(ResultMinor.SAL_FILE_NOT_FOUND, "Select application failed");
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

    for ( CVCPermission field : fields )
    {
      if ((field.getFID() == null || new BigInteger(Hex.parse(field.getFID())).intValue() >= 0x0117)
          && (field.getSFID() == null || Hex.parse(field.getSFID())[0] >= 0x17))
      {
        // there is nothing we can read
      }
      else
      {
        log.debug("{}READ field{}", parent.getLogPrefix(), field.getDataFieldName());

        SelectResult file = null;
        boolean withoutSelect = false;
        if (field.getSFID() == null)
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
              setParentPut(EIDKeys.valueOf(field.getDataFieldName()), new EIDInfoResultNotOnChip());
            }
            else
            {
              log.warn("Other exception as FileNotFoundException was thrown: {}", result.getThrowable());
            }
            log.debug("{}{}Could not read file for {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
          }
          else if (!ArrayUtil.isNullOrEmpty(result.getFileContent()) && result.getFileContent()[0] != 0x00)
          {
            EIDInfoResult value = getASN1Value(result, field.getDataFieldName());
            log.debug("{}{}{} added to eidInfoContainer.", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
            setParentPut(EIDKeys.valueOf(field.getDataFieldName()), value);
          }
          else
          {
            log.debug("{}{}No result (read) for file {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
          }
        }
        else
        {
          setParentPut(EIDKeys.valueOf(field.getDataFieldName()), new EIDInfoResultNotOnChip());
          log.debug("{}{}Could not select file for {}", parent.getLogPrefix(), LOG_DATA, field.getDataFieldName());
        }
      }
    }
    state = SequenceState.TRANSMIT_DONE;
    return getTransmitRequest();
  }

  private void checkAgeVerification(ValidityVerificationResult result) throws ECardException
  {
    if (result.getThrowable() == null)
    {
      setParentPut(EIDKeys.AGE_VERIFICATION, new EIDInfoResultVerification(result.getData()));
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
      setParentPut(EIDKeys.MUNICIPALITY_ID_VERIFICATION, new EIDInfoResultVerification(result.getData()));
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
        setParentPut(EIDKeys.DOCUMENT_VALIDITY, new EIDInfoResultVerification(result.getData()));
        parent.getEIDInfoContainer().setStatus(EIDStatus.VALID);
      }
      else
      {
        log.error("{}[SERVER] Document Validity negative", parent.getLogPrefix());
        log.debug("{}  Response > Create Transmit failed (DocumentValidity): {}",
                  parent.getLogPrefix(),
                  result.getData().toString());
        setParentClear();
        setParentPut(EIDKeys.DOCUMENT_VALIDITY, new EIDInfoResultVerification(result.getData()));
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
    setParentPut(EIDKeys.RESTRICTED_ID, eIDResult);
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

  private void setParentPut(EIDKeys key, EIDInfoResult value)
  {
    parent.getEIDInfoContainer().getInfoMap().put(key, value);
  }

  /**
   * Method to set the checks that should be done on card
   */
  private void setVerificationStates(List<CVCPermission> fieldList)
  {
    this.fields = fieldList;

    // Initialize the verification list
    verifications = new ArrayList<>();

    // Always check for blacklisted ID
    verifications.add(VerificationCommand.BLOCKING_IDENTIFICATION);
    // Always check for document validity
    verifications.add(VerificationCommand.DOCUMENT_VALIDITY);

    if (this.fields.remove(CVCPermission.AUT_AGE_VERIFICATION))
    {
      verifications.add(VerificationCommand.AGE_VERIFICATION);
    }
    if (this.fields.remove(CVCPermission.AUT_RESTRICTED_IDENTIFICATION))
    {
      verifications.add(VerificationCommand.RESTRICTED_IDENTIFICATION);
    }
    if (this.fields.remove(CVCPermission.AUT_MUNICIPALITY_ID_VERIFICATION))
    {
      verifications.add(VerificationCommand.MUNICIPALITY_ID_VERIFICATION);
    }

    // Output which checks are done
    StringBuilder debug = new StringBuilder(LOG_COMMAND + "VerificationStates set - Checks to be done: \n");
    verifications.stream().forEach(s -> debug.append("    o " + s.name() + "\n"));
    log.debug("{}{}", parent.getLogPrefix(), debug.toString());
  }
}
