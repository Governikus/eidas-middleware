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

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSAInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationInfo;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessagingException;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;
import de.governikus.eumw.poseidas.cardbase.constants.ESignConstants;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;
import de.governikus.eumw.poseidas.cardbase.npa.InfoSelector;
import de.governikus.eumw.poseidas.cardbase.npa.NPAUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.batch.Batch;
import de.governikus.eumw.poseidas.cardserver.eac.functions.batch.BatchParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.genkeypair.GenerateKeyPair;
import de.governikus.eumw.poseidas.cardserver.eac.functions.genkeypair.GenerateKeyPairParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.genkeypair.GenerateKeyPairResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.FileParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ps.PseudonymousSignature;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ps.PseudonymousSignatureParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ps.PseudonymousSignatureResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.Read;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattr.ReadAttribute;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattr.ReadAttributeParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattr.ReadAttributeResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattrreq.ReadAttributeRequest;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattrreq.ReadAttributeRequestParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.readattrreq.ReadAttributeRequestResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.ri.RestrictedIdentificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectApplication;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectFile;
import de.governikus.eumw.poseidas.cardserver.eac.functions.select.SelectResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.update.Update;
import de.governikus.eumw.poseidas.cardserver.eac.functions.update.UpdateParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.update.UpdateResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerificationParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattr.WriteAttribute;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattr.WriteAttributeParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattr.WriteAttributeResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattrreq.WriteAttributeRequest;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattrreq.WriteAttributeRequestParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.writeattrreq.WriteAttributeRequestResult;
import de.governikus.eumw.poseidas.ecardcore.core.ECardException;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.ecardid.BlackListConnector;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import iso.std.iso_iec._24727.tech.schema.ConnectionHandleType;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


public class EIDSequenceTransmit
{

  /**
   * LOGGER for this class. Note: Data should be logged only for LEVEL.TRACE
   */
  private static final Log LOG = LogFactory.getLog(EIDSequenceTransmit.class.getName());

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
   * Command for pseudonymous signatures.
   */
  private PseudonymousSignature pseudonymousSignature;

  /**
   * Command for the community ID
   */
  private CommunityIDVerification communityIDVerification;

  /**
   * Command for document validity
   */
  private DocumentValidityVerification documentValidityVerification;

  /**
   * Command for key pair generation.
   */
  private final GenerateKeyPair generateKeyPair;

  /**
   * Command for writing to already existing files.
   */
  private Update update;

  /**
   * Command for writing attribute request.
   */
  private WriteAttributeRequest writeAttributeRequest;

  /**
   * Command for reading attribute request.
   */
  private ReadAttributeRequest readAttributeRequest;

  /**
   * Command for writing attributes.
   */
  private WriteAttribute writeAttribute;

  /**
   * Command for reading attributes.
   */
  private ReadAttribute readAttribute;

  /**
   * Instance for connecting the CA (submit public key, receive signed certificate).
   */
  private CAConnection caConnection = null;

  /**
   * {@link PSAInfo} selected to use.
   */
  private PSAInfo selectedPSAInfo = null;

  /**
   * Fields allowed to be read selected by the user on client side. Note: it is imperative that the field
   * "install qualified certificate" is on last position in the list, if present.
   */
  private List<CVCPermission> fields;

  /**
   * List of verification commands to be done on card. List provides correct sort of verifications in process
   */
  private List<VerificationCommand> verifications;

  /**
   * Stores the parameters used for different versions of pseudonymous signature.
   */
  private final Map<VerificationCommand, PseudonymousSignatureParameter> psParameterMap = new EnumMap<>(VerificationCommand.class);

  /**
   * State of transmit process
   */
  private SequenceState state;

  public enum SequenceState
  {
    BATCH_COMMANDS,
    BATCH_DATA,
    READ_PROVIDED_ATTRIBUTES,
    QES_READ_CIA,
    QES_EXAMINE_FILES,
    QES_ERASE_OLD_CERTS,
    QES_GENERATE_KEY,
    QES_WRITE_NEW_CERTS,
    TRANSMIT_DONE
  }

  private enum VerificationCommand
  {
    DOCUMENT_VALIDITY,
    AGE_VERIFICATION,
    RESTRICTED_IDENTIFICATION,
    BLOCKING_IDENTIFICATION,
    MUNICIPALITY_ID_VERIFICATION,
    PSEUDONYMOUS_SIGNATURE_CREDENTIALS,
    PSEUDONYMOUS_SIGNATURE_MESSAGE,
    PSEUDONYMOUS_SIGNATURE_AUTHENTICATION
  }

  /**
   * Flag indicating if QES is to be installed on the card.
   */
  private boolean installQES;

  /**
   * File ID of EF.PrKD (information about private keys on card).
   */
  private byte[] fidEFPrKD;

  /**
   * File ID of EF.CD (information about certificates on card).
   */
  private byte[] fidEFCD;

  /**
   * ID of private key (on card).
   */
  private byte[] prKID;

  /**
   * ID of CA certificate file (on card).
   */
  private byte[] fidCACert;

  /**
   * Length of CA certificate file.
   */
  private byte[] caFileLength;

  /**
   * Newly received CA certificate.
   */
  private byte[] caCert;

  /**
   * ID of certificate file (on card).
   */
  private byte[] fidCert;

  /**
   * Length of certificate file.
   */
  private byte[] certFileLength;

  /**
   * Newly received certificate.
   */
  private byte[] cert;

  /**
   * Attribute request.
   */
  private byte[] attributeRequest;

  /**
   * List of requests for specific attributes.
   */
  private List<ASN1> specificAttributesToRead = null;

  /**
   * Number of commands for writing generic attributes.
   */
  private int numGenericWrites = 0;

  /**
   * Number of commands for writing specific attributes.
   */
  private int numSpecificWrites = 0;

  /**
   * Set of specific attributes already read.
   */
  private final Set<BigInteger> attributesCollected = new HashSet<>();

  /**
   * Instance to handle all transmits for a EIDSequence
   *
   * @param sequence
   */
  EIDSequenceTransmit(EIDSequence sequence, CAConnection caConnection)
  {
    parent = sequence;
    ConnectionHandleType connectionHandle = parent.getConnectionHandle();
    byte[] slotHandleFromConnectionHandle = connectionHandle.getSlotHandle();
    slotHandle = slotHandleFromConnectionHandle == null ? new byte[]{0} : slotHandleFromConnectionHandle;
    this.caConnection = caConnection;
    transmit = new TransmitAPDU(parent.getEACFinal().getSM());

    // Create all objects required for transmit commands
    select = new SelectApplication(transmit);
    selectFile = new SelectFile(transmit);
    readFile = new Read(transmit);
    transmitBatch = new Batch(transmit);
    generateKeyPair = new GenerateKeyPair(transmit);
    update = new Update(transmit);
    writeAttributeRequest = new WriteAttributeRequest(transmit);
    readAttributeRequest = new ReadAttributeRequest(transmit);
    writeAttribute = new WriteAttribute(transmit);
    readAttribute = new ReadAttribute(transmit);
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
    LOG.debug(parent.getLogPrefix() + "[Transmit] Handle response: " + state.name());
    // Handle the converted result from eCard by result step to be able to handle mCard batch
    transmitResult = transmitBatch.resultStep(transmitResult.getData());
    if (transmitResult.getThrowable() != null
        && transmitResult.getThrowable() instanceof SecureMessagingException)
    {
      parent.getEIDInfoContainer().setStatus(EIDStatus.NOT_AUTHENTIC);
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, transmitResult.getThrowable());
    }

    switch (state)
    {
      case BATCH_COMMANDS:
        return handleBatchCommands(transmitResult);
      case BATCH_DATA:
        return handleBatchData(transmitResult);
      case READ_PROVIDED_ATTRIBUTES:
        return handleReadProvidedAttributes(transmitResult);
      case QES_READ_CIA:
        return handleQESReadCIA(transmitResult);
      case QES_EXAMINE_FILES:
        return handleQESExamineFiles(transmitResult);
      case QES_ERASE_OLD_CERTS:
        return handleQESEraseCerts(transmitResult);
      case QES_GENERATE_KEY:
        return handleQESGenerateKey(transmitResult);
      case QES_WRITE_NEW_CERTS:
        return handleQESWriteCerts(transmitResult);
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

    if (verifications.contains(VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION))
    {
      listBatches.addAll(getCommandPseudonymousSignature(VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION));
    }

    // Always select application to be able to handle commands on card
    listBatches.addAll(select.create(getFileParameterSelectApplication()));

    if ("true".equalsIgnoreCase(System.getProperty("attributeprovider.enabled")))
    {
      listBatches.addAll(getCommandReadAttributeRequest());
    }
    else
    {
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
          case PSEUDONYMOUS_SIGNATURE_CREDENTIALS:
          case PSEUDONYMOUS_SIGNATURE_MESSAGE:
            listBatches.addAll(getCommandPseudonymousSignature(verification));
            break;
          case PSEUDONYMOUS_SIGNATURE_AUTHENTICATION:
            // already handled
            break;
        }
      }

      // try to read specific and generic attributes
      listBatches.addAll(getCommandReadSpecificAttributes());
      for ( CVCPermission field : fields )
      {
        // do not read fields other than generic attributes here
        if (field.getSFID() != null && Hex.parse(field.getSFID())[0] >= 0x17)
        {
          ReadParameter readParameter = new ReadParameter(0, 65536, Hex.parse(field.getSFID())[0]);
          LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for " + field.getDataFieldName());
          listBatches.addAll(readFile.create(readParameter));
        }
        // do not read fields other than generic attributes here
        else if (field.getFID() != null && new BigInteger(Hex.parse(field.getFID())).intValue() >= 0x0117)
        {
          FileParameter file = new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID),
                                                 Hex.parse(field.getFID()), true);
          LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create select for " + field.getDataFieldName());
          listBatches.addAll(selectFile.create(file));
          LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for this field");
          listBatches.addAll(readFile.create(null));
        }
      }
    }

    BatchParameter batchParameters = new BatchParameter(listBatches);
    return transmitBatch.parameterStep(batchParameters, slotHandle);
  }

  private Object getBatchData() throws ECardException
  {
    // Batch list to be filled
    List<InputAPDUInfoType> batchList = new ArrayList<>();

    if ("true".equalsIgnoreCase(System.getProperty("attributeprovider.enabled")))
    {
      batchList.addAll(getCommandWriteGenericAttributes());
      batchList.addAll(getCommandWriteSpecificAttributes());
    }
    else
    {
      StringBuilder tempInfo = new StringBuilder("FIELDS:\n");
      for ( CVCPermission field : fields )
      {
        tempInfo.append(" o " + field.getDataFieldName());
      }
      LOG.debug(parent.getLogPrefix() + LOG_DATA + tempInfo.toString());

      for ( CVCPermission field : fields )
      {
        if (field != null)
        {
          switch (field)
          {
          // These fields should not be read again because they were checked by verification and will not
          // return
          // a data result
            case AUT_SF_AGE_VERIFICATION:
            case AUT_AGE_VERIFICATION:
            case AUT_SF_MUNICIPALITY_ID_VERIFICATION:
            case AUT_MUNICIPALITY_ID_VERIFICATION:
            case AUT_SF_RESTRICTED_IDENTIFICATION:
            case AUT_RESTRICTED_IDENTIFICATION:
            case AUT_SF_PSA:
            case AUT_PSA:
            case AUT_SF_PSC:
            case AUT_SF_PSM:
              continue;
            default:
          }

          // do not read fields with generic attributes here
          if (field.getSFID() != null && Hex.parse(field.getSFID())[0] < 0x17)
          {
            ReadParameter readParameter = new ReadParameter(0, 65536, Hex.parse(field.getSFID())[0]);
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for " + field.getDataFieldName());
            batchList.addAll(readFile.create(readParameter));
          }
          // do not read fields with generic attributes here
          else if (field.getFID() != null && new BigInteger(Hex.parse(field.getFID())).intValue() < 0x0117)
          {
            FileParameter file = new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID),
                                                   Hex.parse(field.getFID()), true);
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create select for " + field.getDataFieldName());
            batchList.addAll(selectFile.create(file));
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for this field");
            batchList.addAll(readFile.create(null));
          }
          else if (field == CVCPermission.AUT_INSTALL_QUALIFIED_CERTIFICATE)
          {
            // first step of QES installment: read EF.OD in CIA
            FileParameter file = new FileParameter(ESignConstants.AID_CIA_ESIGN.toArray(),
                                                   ESignConstants.EF_OD.toArray(), true);
            batchList.addAll(select.create(file));
            batchList.addAll(selectFile.create(file));
            batchList.addAll(readFile.create(null));
          }
          else
          {
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Unknown handle on: " + field.getDataFieldName());
          }
        }
        else
        {
          LOG.debug(parent.getLogPrefix() + LOG_DATA + "Empty field");
        }
      }
      batchList.addAll(getCommandWriteAttributeRequest());
    }

    if (batchList.isEmpty())
    {
      LOG.debug(parent.getLogPrefix() + LOG_DATA + "No data field to be read");
      state = SequenceState.TRANSMIT_DONE;
      return getTransmitRequest();
    }
    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getReadProvidedAttributes() throws ECardException
  {
    // Batch list to be filled
    List<InputAPDUInfoType> batchList = new ArrayList<>();
    batchList.addAll(getCommandReadSpecificAttributes());

    for ( CVCPermission field : fields )
    {
      // only try to read values not already there
      if (checkParentPresent(EIDKeys.valueOf(field.getDataFieldName())))
      {
        continue;
      }

      // do not read fields other than generic attributes here
      if (field.getSFID() != null && Hex.parse(field.getSFID())[0] >= 0x17)
      {
        ReadParameter readParameter = new ReadParameter(0, 65536, Hex.parse(field.getSFID())[0]);
        LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for " + field.getDataFieldName());
        batchList.addAll(readFile.create(readParameter));
      }
      // do not read fields other than generic attributes here
      else if (field.getFID() != null && new BigInteger(Hex.parse(field.getFID())).intValue() >= 0x0117)
      {
        FileParameter file = new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID),
                                               Hex.parse(field.getFID()), true);
        LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create select for " + field.getDataFieldName());
        batchList.addAll(selectFile.create(file));
        LOG.debug(parent.getLogPrefix() + LOG_DATA + "Create read for this field");
        batchList.addAll(readFile.create(null));
      }
    }

    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getQESReadCIA()
  {
    List<InputAPDUInfoType> batchList = new ArrayList<>();
    FileParameter file = new FileParameter(ESignConstants.AID_CIA_ESIGN.toArray(), this.fidEFPrKD, true);
    batchList.addAll(selectFile.create(file));
    batchList.addAll(readFile.create(null));
    file = new FileParameter(ESignConstants.AID_CIA_ESIGN.toArray(), this.fidEFCD, true);
    batchList.addAll(selectFile.create(file));
    batchList.addAll(readFile.create(null));
    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getQESExamineFiles()
  {
    List<InputAPDUInfoType> batchList = new ArrayList<>();
    FileParameter file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCACert, true, true);
    batchList.addAll(select.create(file));
    batchList.addAll(selectFile.create(file));
    file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCert, true, true);
    batchList.addAll(selectFile.create(file));
    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getQESEraseCerts()
  {
    List<InputAPDUInfoType> batchList = new ArrayList<>();
    FileParameter file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCACert, true);
    batchList.addAll(selectFile.create(file));

    BigInteger caFLength = new BigInteger(1, this.caFileLength);
    int remaining = caFLength.intValue();
    do
    {
      int numBytes = Math.min(ESignConstants.RW_BLOCK_SIZE, remaining);
      byte[] input = new byte[numBytes];
      ByteUtil.fill(input, (byte)0, 0, numBytes);
      UpdateParameter writeParameter = new UpdateParameter(input);
      batchList.addAll(update.create(writeParameter));
      remaining -= numBytes;
    }
    while (remaining > 0);

    file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCert, true);
    batchList.addAll(selectFile.create(file));

    BigInteger certFLength = new BigInteger(1, this.certFileLength);
    remaining = certFLength.intValue();
    do
    {
      int numBytes = Math.min(ESignConstants.RW_BLOCK_SIZE, remaining);
      byte[] input = new byte[numBytes];
      ByteUtil.fill(input, (byte)0, 0, numBytes);
      UpdateParameter writeParameter = new UpdateParameter(input);
      batchList.addAll(update.create(writeParameter));
      remaining -= numBytes;
    }
    while (remaining > 0);

    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getQESGenerateKey()
  {
    List<InputAPDUInfoType> batchList = new ArrayList<>();
    GenerateKeyPairParameter gkpParameter = new GenerateKeyPairParameter(this.prKID);
    batchList.addAll(generateKeyPair.create(gkpParameter));
    BatchParameter batchParameter = new BatchParameter(batchList);
    return transmitBatch.parameterStep(batchParameter, slotHandle);
  }

  private Object getQESWriteCert() throws ECardException
  {
    BigInteger caFLength = new BigInteger(1, this.caFileLength);
    BigInteger certFLength = new BigInteger(1, this.certFileLength);

    if (this.caCert.length > caFLength.intValue())
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                               "CA certificate is too long for storage on card");
    }
    if (this.cert.length > certFLength.intValue())
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                               "Certificate is too long for storage on card");
    }

    List<InputAPDUInfoType> batchList = new ArrayList<>();
    FileParameter file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCACert, true);
    batchList.addAll(selectFile.create(file));

    int remaining = this.caCert.length;
    int i = 0;
    do
    {
      int numBytes = Math.min(ESignConstants.RW_BLOCK_SIZE, remaining);
      byte[] input = ByteUtil.subbytes(this.caCert,
                                       i * ESignConstants.RW_BLOCK_SIZE,
                                       i * ESignConstants.RW_BLOCK_SIZE + numBytes);
      UpdateParameter writeParameter = new UpdateParameter(input, i * ESignConstants.RW_BLOCK_SIZE);
      batchList.addAll(update.create(writeParameter));
      remaining -= numBytes;
      i++;
    }
    while (remaining > 0);

    file = new FileParameter(ESignConstants.AID_ESIGN.toArray(), this.fidCert, true);
    batchList.addAll(selectFile.create(file));
    remaining = this.cert.length;
    i = 0;
    do
    {
      int numBytes = Math.min(ESignConstants.RW_BLOCK_SIZE, remaining);
      byte[] input = ByteUtil.subbytes(this.cert,
                                       i * ESignConstants.RW_BLOCK_SIZE,
                                       i * ESignConstants.RW_BLOCK_SIZE + numBytes);
      UpdateParameter writeParameter = new UpdateParameter(input, i * ESignConstants.RW_BLOCK_SIZE);
      batchList.addAll(update.create(writeParameter));
      remaining -= numBytes;
      i++;
    }
    while (remaining > 0);

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

  private List<InputAPDUInfoType> getCommandPseudonymousSignature(VerificationCommand v)
    throws ECardException
  {
    if (this.pseudonymousSignature == null)
    {
      this.pseudonymousSignature = new PseudonymousSignature(this.transmit);
    }
    SessionInput si = this.parent.getSessionInput();
    try
    {
      SecurityInfos cardSecurity = NPAUtil.fromCardSecurityBytes(parent.getEACFinal().getCardSecurityBytes());
      this.selectedPSAInfo = InfoSelector.selectPSAInfo(cardSecurity.getPSAInfo(), this.parent.getEACFinal()
                                                                                              .getCaData()
                                                                                              .getCaInfo());
      // select PSInfo
      PSInfo psInfo = v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION ? this.selectedPSAInfo
        : v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS ? cardSecurity.getPSCInfo().get(0)
          : cardSecurity.getPSMInfo().get(0);
      PseudonymousSignatureParameter psParam = new PseudonymousSignatureParameter(
                                                                                  psInfo,
                                                                                  InfoSelector.selectPSPublicKeyInfo(cardSecurity.getPSPublicKeyInfo(),
                                                                                                                     psInfo),
                                                                                  this.parent.getCVC()
                                                                                             .getPSKey(),
                                                                                  v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION
                                                                                    ? new ASN1(
                                                                                               (byte)0x81,
                                                                                               this.parent.getEACFinal()
                                                                                                          .getEphemeralCardKey()).getEncoded()
                                                                                    : v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_MESSAGE
                                                                                      ? si.getPsMessage()
                                                                                      : null,
                                                                                  v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS
                                                                                    ? si.getPscFidList()
                                                                                    : null,
                                                                                  v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS
                                                                                    ? si.isPscIncludeSpecific()
                                                                                    : false);
      this.psParameterMap.put(v, psParam);
      return this.pseudonymousSignature.create(psParam);
    }
    catch (Exception e)
    {
      throw new ECardException(ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED,
                               "Unable to create command for pseudonymous signature identification", e);
    }
  }

  private boolean mustWriteAttributeRequest()
  {
    if (!this.fields.contains(CVCPermission.AUT_WRITE_ATT_REQUEST))
    {
      return false;
    }

    return this.specificAttributesToRead != null && !this.specificAttributesToRead.isEmpty();
  }

  private List<InputAPDUInfoType> getCommandWriteAttributeRequest()
  {
    if (!this.mustWriteAttributeRequest())
    {
      return new ArrayList<>(0);
    }

    ASN1 set;
    try
    {
      set = new ASN1(ASN1Constants.UNIVERSAL_TAG_SET_CONSTRUCTED, new byte[0]);
      if (this.specificAttributesToRead != null)
      {
        set.addChildElements(this.specificAttributesToRead, set);
      }
    }
    catch (IOException e)
    {
      return new ArrayList<>(0);
    }

    if (this.writeAttributeRequest == null)
    {
      this.writeAttributeRequest = new WriteAttributeRequest(this.transmit);
    }

    WriteAttributeRequestParameter parameter = new WriteAttributeRequestParameter(
                                                                                  parent.getCVC()
                                                                                        .getSectorPublicKeyHash(),
                                                                                  set.getEncoded());
    return this.writeAttributeRequest.create(parameter);
  }

  private List<InputAPDUInfoType> getCommandReadAttributeRequest()
  {
    if (this.readAttributeRequest == null)
    {
      this.readAttributeRequest = new ReadAttributeRequest(this.transmit);
    }
    ReadAttributeRequestParameter parameter = new ReadAttributeRequestParameter();
    return this.readAttributeRequest.create(parameter);
  }

  private List<InputAPDUInfoType> getCommandWriteGenericAttributes()
  {
    if (this.update == null)
    {
      this.update = new Update(this.transmit);
    }

    List<InputAPDUInfoType> returnList = new ArrayList<>();

    if (this.attributeRequest != null)
    {
      // attribute provider logic
    }

    this.numGenericWrites = returnList.size();
    return returnList;
  }

  private List<InputAPDUInfoType> getCommandWriteSpecificAttributes()
  {
    if (this.writeAttribute == null)
    {
      this.writeAttribute = new WriteAttribute(this.transmit);
    }

    List<byte[]> attributeList = new ArrayList<>();

    if (this.attributeRequest != null)
    {
      // attribute provider logic
    }

    WriteAttributeParameter parameter = new WriteAttributeParameter(attributeList);
    List<InputAPDUInfoType> returnList = this.writeAttribute.create(parameter);
    this.numSpecificWrites = returnList.size();
    return returnList;
  }

  private List<InputAPDUInfoType> getCommandReadSpecificAttributes()
  {
    byte[] requests = parent.getSessionInput().getSpecificRequests();
    if (!this.fields.contains(CVCPermission.AUT_READ_SPEC_ATT) || requests == null || requests.length == 0)
    {
      return new ArrayList<>(0);
    }

    if (this.specificAttributesToRead == null)
    {
      this.specificAttributesToRead = new ArrayList<>();
      try
      {
        ASN1 set = new ASN1(requests);
        this.specificAttributesToRead.addAll(set.getChildElementList());
      }
      catch (IOException e)
      {
        this.specificAttributesToRead.clear();
      }
    }

    if (this.specificAttributesToRead.isEmpty())
    {
      return new ArrayList<>(0);
    }

    if (this.readAttribute == null)
    {
      this.readAttribute = new ReadAttribute(this.transmit);
    }
    ReadAttributeParameter parameter = new ReadAttributeParameter(parent.getCVC().getSectorPublicKeyHash());
    return this.readAttribute.create(parameter);
  }

  private FileParameter getFileParameterSelectApplication()
  {
    return new FileParameter(Hex.parse(EIDConstants.EID_APPLICATION_AID),
                             Hex.parse(EIDConstants.EID_FID_DG01_DOCUMENT_TYPE), true);
  }

  private RestrictedIdentificationParameter getParameterRestrictedIdentification(boolean ri)
    throws IOException
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
    LOG.debug(parent.getLogPrefix() + "[Transmit] Get next transmit: " + state.name());
    switch (state)
    {
      case BATCH_COMMANDS:
        return getBatchCommands();
      case BATCH_DATA:
        return getBatchData();
      case READ_PROVIDED_ATTRIBUTES:
        return getReadProvidedAttributes();
      case QES_READ_CIA:
        return getQESReadCIA();
      case QES_EXAMINE_FILES:
        return getQESExamineFiles();
      case QES_ERASE_OLD_CERTS:
        return getQESEraseCerts();
      case QES_GENERATE_KEY:
        return getQESGenerateKey();
      case QES_WRITE_NEW_CERTS:
        return getQESWriteCert();
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
          String state = getASNAdress(addressASN, (byte)0xac, isBirthPlace);
          String country = getASNAdress(addressASN, (byte)0xad, isBirthPlace);
          String zipCode = getASNAdress(addressASN, (byte)0xae, isBirthPlace);
          return new EIDInfoResultPlaceStructured(street, city, state, country, zipCode);
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
          return new EIDInfoResultString(new String(new ASN1(textASN.getValue()).getValue(),
                                                    StandardCharsets.UTF_8));
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
              throw new IOException("Unexpected text format: "
                                    + new String(textASN.getValue(), StandardCharsets.UTF_8));
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
      LOG.debug(parent.getLogPrefix() + LOG_DATA + "[ASN1 Simple] : " + fieldValue);
      return new EIDInfoResultString(result.toString());
    }
    catch (IOException e)
    {
      LOG.error(parent.getLogPrefix() + LOG_DATA + "Can't get FileContent for field: " + dataFieldName, e);
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
    if (verifications.contains(VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION))
    {
      handleBatchCommandPseudonymousSignature(transmitResult,
                                              additionalResults,
                                              VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION);
      additionalResults += 2;
    }
    // Check if select application was successful
    SelectResult selected = select.evaluate(transmitResult, new int[]{additionalResults});
    // Select is the first additional result to count for commands
    additionalResults++;
    if (selected.isSelected())
    {
      LOG.debug(parent.getLogPrefix() + LOG_SELECT + "Select application successful");

      if ("true".equalsIgnoreCase(System.getProperty("attributeprovider.enabled")))
      {
        handleCommandReadAttributeRequest(transmitResult, additionalResults);
      }
      else
      {
        for ( VerificationCommand verification : verifications )
        {
          LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Command checked: " + verification.name()
                    + " at position " + additionalResults);
          switch (verification)
          {
            case AGE_VERIFICATION:
              handleBatchCommandAgeVerification(transmitResult, additionalResults);
              additionalResults++;
              break;
            case BLOCKING_IDENTIFICATION:
              // Restricted identifications return two result. First is only that result is OK
              LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Start: " + verification.name());
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
              additionalResults++;
              handleBatchCommandRestrictedIdentification(transmitResult, additionalResults);
              additionalResults++;
              break;
            case PSEUDONYMOUS_SIGNATURE_CREDENTIALS:
            case PSEUDONYMOUS_SIGNATURE_MESSAGE:
              handleBatchCommandPseudonymousSignature(transmitResult, additionalResults, verification);
              additionalResults += 2;
              break;
            case PSEUDONYMOUS_SIGNATURE_AUTHENTICATION:
              // already handled
              break;
          }
          LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "NEXT >>> ");
        }

        if (this.canReadSpecificAttributes())
        {
          handleCommandReadSpecificAttributes(transmitResult, additionalResults);
          additionalResults += 2;
        }

        for ( CVCPermission field : fields )
        {
          if ((field.getFID() == null || new BigInteger(Hex.parse(field.getFID())).intValue() < 0x0117)
              && (field.getSFID() == null || Hex.parse(field.getSFID())[0] < 0x17))
          {
            // only handle generic attributes here
            continue;
          }
          else
          {
            LOG.debug(parent.getLogPrefix() + "READ field" + field.getDataFieldName());

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
                LOG.debug(parent.getLogPrefix() + LOG_DATA + "Could not read file for "
                          + field.getDataFieldName());
              }
              else if (!ArrayUtil.isNullOrEmpty(result.getFileContent())
                       && result.getFileContent()[0] != 0x00)
              {
                EIDInfoResult value = getASN1Value(result, field.getDataFieldName());
                LOG.debug(parent.getLogPrefix() + LOG_DATA + field.getDataFieldName()
                          + "' added to eidInfoContainer.");
                setParentPut(EIDKeys.valueOf(field.getDataFieldName()), value);
              }
              else
              {
                LOG.debug(parent.getLogPrefix() + LOG_DATA + "No result (read) for file "
                          + field.getDataFieldName());
              }
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

  private void handleBatchCommandAgeVerification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    ValidityVerificationResult result = ageVerification.evaluate(transmitResult, new int[]{index});
    checkAgeVerification(result);
  }

  private void handleBatchCommandBlockingIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Evaluate RI with MCard");
    RestrictedIdentificationResult result = restrictedIdentification.evaluate(transmitResult,
                                                                              new int[]{index});
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Result from MCard: " + result);
    checkBlockingIdentification(result);
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "check BlockingIdentification done");
  }

  private void handleBatchCommandCommunityIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    ValidityVerificationResult result = communityIDVerification.evaluate(transmitResult, new int[]{index});
    checkCommunityIdentification(result);
  }


  private void handleBatchCommandDocumentValidity(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    ValidityVerificationResult result = documentValidityVerification.evaluate(transmitResult,
                                                                              new int[]{index});
    checkDocumentValidity(result);
  }

  private void handleBatchCommandRestrictedIdentification(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    RestrictedIdentificationResult result = restrictedIdentification.evaluate(transmitResult,
                                                                              new int[]{index});
    checkRestrictedIdentification(result);
  }

  private void handleBatchCommandPseudonymousSignature(TransmitAPDUResult transmitResult,
                                                       int index,
                                                       VerificationCommand v) throws ECardException
  {
    PseudonymousSignatureResult result = this.pseudonymousSignature.evaluate(transmitResult,
                                                                             new int[]{index, index + 1});
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Pseudonymous signature failed: "
                                                                 + result.getThrowable());
    }

    PseudonymousSignatureParameter psp = this.psParameterMap.get(v);
    // verification for PSC (how if we do not have all credentials?)
    Boolean verified = null;
    if (v != VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS)
    {
      if (PseudonymousSignature.checkSignature(psp, result))
      {
        verified = true;
      }
      else
      {
        verified = false;
      }
    }

    if (v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION)
    {
      byte[] blockingID = null;
      byte[] restrictedID = null;
      try
      {
        blockingID = this.selectedPSAInfo.getPS1AuthInfoInt() == 0 ? result.getFirstKey()
          : this.selectedPSAInfo.getPS2AuthInfoInt() == 0 ? result.getSecondKey() : null;
        restrictedID = this.selectedPSAInfo.getPS1AuthInfoInt() == 1 ? result.getFirstKey()
          : this.selectedPSAInfo.getPS2AuthInfoInt() == 1 ? result.getSecondKey() : null;
      }
      catch (IOException e)
      {
        // nothing
      }
      if (blockingID == null)
      {
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                                 "Blocking identification verification failed: "
                                   + "Result contains no ID to use");
      }
      this.checkBlockingIdentification(blockingID);
      this.checkRestrictedIdentification(restrictedID, null);
    }
    try
    {
      this.setParentPut(v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION ? EIDKeys.PSA
                          : v == VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS ? EIDKeys.PSC
                            : EIDKeys.PSM,
                        new EIDInfoResultPseudonymousSignature(result.getFirstKey(), result.getSecondKey(),
                                                               result.getSignature(), psp, verified));
    }
    catch (IOException e)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Results from pseudonymous signature could not be extracted");
    }
  }

  private boolean handleCommandWriteAttributeRequest(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    if (!this.mustWriteAttributeRequest())
    {
      return false;
    }

    WriteAttributeRequestResult result = writeAttributeRequest.evaluate(transmitResult, new int[]{index,
                                                                                                  index + 1,
                                                                                                  index + 2});
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Write attribute request failed and threw an exception: "
                                 + result.getThrowable());
    }
    if (!result.getData())
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Write attribute request returned false");
    }
    return true;
  }

  private void handleCommandReadAttributeRequest(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    ReadAttributeRequestResult result = readAttributeRequest.evaluate(transmitResult, new int[]{index});
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Read attribute request failed and threw an exception: "
                                 + result.getThrowable());
    }

    byte[] attributeRequest = result.getData();
    if (attributeRequest == null || attributeRequest.length == 0)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Read attribute request returned nothing");
    }
    this.attributeRequest = attributeRequest;
  }

  private void handleCommandWriteSpecificAttributes(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    int[] indices = new int[this.numSpecificWrites];
    for ( int i = 0 ; i < this.numSpecificWrites ; i++ )
    {
      indices[i] = index + i;
    }
    WriteAttributeResult result = writeAttribute.evaluate(transmitResult, indices);
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Write attribute failed and threw an exception: " + result.getThrowable());
    }

    if (!result.getData())
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Write attribute returned false");
    }
  }

  private void handleCommandWriteGenericAttributes(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    int[] indices = new int[this.numGenericWrites];
    for ( int i = 0 ; i < this.numGenericWrites ; i++ )
    {
      indices[i] = index + i;
    }
    UpdateResult result = update.evaluate(transmitResult, indices);
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Write failed and threw an exception: "
                                                                 + result.getThrowable());
    }

    if (!result.getData())
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "Write returned false");
    }
  }

  private void handleCommandReadSpecificAttributes(TransmitAPDUResult transmitResult, int index)
    throws ECardException
  {
    if (!this.canReadSpecificAttributes())
    {
      return;
    }

    ReadAttributeResult result = readAttribute.evaluate(transmitResult, new int[]{index, index + 1});
    if (result.getThrowable() != null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Read specific attributes failed and threw an exception: "
                                 + result.getThrowable());
    }

    List<byte[]> resultData = result.getData();
    if (resultData == null || resultData.isEmpty())
    {
      LOG.debug(parent.getLogPrefix() + LOG_DATA + "Read specific attributes returned no data");
      return;
    }

    try
    {
      List<ASN1> attributes = new ArrayList<>();
      for ( byte[] singleResult : resultData )
      {
        attributes.add(new ASN1(singleResult));
        // add a 0x01 byte to avoid leading zeroes being cut
        this.attributesCollected.add(new BigInteger(ByteUtil.combine(new byte[]{1}, singleResult)));
      }

      List<ASN1> tempAttributes = new ArrayList<>(this.specificAttributesToRead);
      for ( ASN1 singleRequest : tempAttributes )
      {
        for ( ASN1 singleResult : attributes )
        {
          // NOTE this is only a hint that the request is already fulfilled
          if (singleRequest.getChildElementsByTag(0x06)[0].equals(singleResult.getChildElementsByTag(0x06)[0]))
          {
            this.specificAttributesToRead.remove(singleRequest);
          }
        }
      }
    }
    catch (IOException e)
    {
      // nothing yet
    }

    List<byte[]> resultList = new ArrayList<>();
    for ( BigInteger b : this.attributesCollected )
    {
      // remove the 0x01 byte at the beginning
      resultList.add(ByteUtil.subbytes(b.toByteArray(), 1));
    }

    setParentPut(EIDKeys.SPECIFIC_ATTRIBUTES, new EIDInfoResultListByteArray(resultList));
  }

  private Object handleQESReadCIA(TransmitAPDUResult transmitResult) throws ECardException
  {
    SelectResult file = selectFile.evaluate(transmitResult, new int[]{0});
    if (file.isSelected())
    {
      ReadResult result = readFile.evaluate(transmitResult, new int[]{1});
      try
      {
        this.prKID = NPAUtil.evaluateEFPrKD(new ASN1(0x30, result.getFileContent()));
      }
      catch (IOException e)
      {
        throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, e.getMessage(), e);
      }
    }

    file = selectFile.evaluate(transmitResult, new int[]{2});
    if (file.isSelected())
    {
      ReadResult result = readFile.evaluate(transmitResult, new int[]{3});
      Map<String, byte[]> resultMap = null;
      try
      {
        resultMap = NPAUtil.evaluateEFCD(new ASN1(0x30, result.getFileContent()));
      }
      catch (IOException e)
      {
        throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, e.getMessage(), e);
      }
      this.fidCACert = resultMap.get(NPAUtil.FID_CACERT);
      this.fidCert = resultMap.get(NPAUtil.FID_CERT);
    }

    state = SequenceState.QES_EXAMINE_FILES;
    return getTransmitRequest();
  }

  private Object handleQESExamineFiles(TransmitAPDUResult transmitResult) throws ECardException
  {
    SelectResult app = select.evaluate(transmitResult, new int[]{0});
    if (!app.isSelected())
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, "Could not select eSign application");
    }
    SelectResult file = selectFile.evaluate(transmitResult, new int[]{1});
    if (!file.isSelected())
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                               "Could not select CA certificate file");
    }
    try
    {
      this.caFileLength = NPAUtil.evaluateFCP(file.getFCP());
    }
    catch (IOException e)
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, e.getMessage(), e);
    }

    file = selectFile.evaluate(transmitResult, new int[]{2});
    if (!file.isSelected())
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, "Could not select certificate file");
    }
    try
    {
      this.certFileLength = NPAUtil.evaluateFCP(file.getFCP());
    }
    catch (IOException e)
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, e.getMessage(), e);
    }


    state = SequenceState.QES_ERASE_OLD_CERTS;
    return getTransmitRequest();
  }

  private Object handleQESEraseCerts(TransmitAPDUResult transmitResult) throws ECardException
  {
    for ( byte[] rAPDU : transmitResult.getData().getOutputAPDU() )
    {
      if (rAPDU == null || rAPDU.length != 2 || rAPDU[0] != (byte)0x90 || rAPDU[1] != 0x00)
      {
        throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                                 "Error in erasing old certificates");
      }
    }

    state = SequenceState.QES_GENERATE_KEY;
    return getTransmitRequest();
  }

  private Object handleQESGenerateKey(TransmitAPDUResult transmitResult) throws ECardException
  {
    GenerateKeyPairResult key = generateKeyPair.evaluate(transmitResult, new int[]{0});
    byte[] keyData = key.getData();
    if (keyData == null || keyData.length == 0)
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                               "Generation of key failed - no public key returned");
    }

    // submit key to CA and receive certificates, extend (probably many more parameters required...)
    String dn;
    try
    {
      Map<EIDKeys, EIDInfoResult> data = parent.getEIDInfoContainer().getInfoMap();
      dn = "CN=" + ((EIDInfoResultString)data.get(EIDKeys.GIVEN_NAMES)).getResult() + " "
           + ((EIDInfoResultString)data.get(EIDKeys.FAMILY_NAMES)).getResult();
      EIDInfoResult residence = data.get(EIDKeys.PLACE_OF_RESIDENCE);
      if (residence instanceof EIDInfoResultPlaceStructured)
      {
        EIDInfoResultPlaceStructured structuredPlace = (EIDInfoResultPlaceStructured)residence;
        if (structuredPlace.getCity() != null)
        {
          dn += ",L=" + structuredPlace.getCity();
        }
        if (structuredPlace.getState() != null)
        {
          dn += ",ST=" + structuredPlace.getState();
        }
        dn += ",C=" + (structuredPlace.getCountry() == null ? "DE" : structuredPlace.getCountry());
      }
    }
    catch (Exception e)
    {
      dn = null;
    }
    List<byte[]> receivedCerts = this.caConnection.submitPublicKey(keyData, dn);

    if (receivedCerts == null || receivedCerts.size() != 2)
    {
      throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                               "CA did not deliver two certificates");
    }
    this.caCert = receivedCerts.get(0);
    this.cert = receivedCerts.get(1);

    state = SequenceState.QES_WRITE_NEW_CERTS;
    return getTransmitRequest();
  }

  private Object handleQESWriteCerts(TransmitAPDUResult transmitResult) throws ECardException
  {
    for ( byte[] rAPDU : transmitResult.getData().getOutputAPDU() )
    {
      if (rAPDU == null || rAPDU.length != 2 || rAPDU[0] != (byte)0x90 || rAPDU[1] != 0x00)
      {
        this.caConnection.reportWrite(false);
        throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                                 "Error in writing new certificates");
      }
    }
    this.caConnection.reportWrite(true);
    state = SequenceState.TRANSMIT_DONE;
    return getTransmitRequest();
  }

  private Object handleBatchData(TransmitAPDUResult transmitResult) throws ECardException
  {
    int position = 0;

    if ("true".equalsIgnoreCase(System.getProperty("attributeprovider.enabled")))
    {
      handleCommandWriteGenericAttributes(transmitResult, position);
      position += this.numGenericWrites;
      handleCommandWriteSpecificAttributes(transmitResult, position);
      state = SequenceState.TRANSMIT_DONE;
    }
    else
    {
      this.installQES = false;
      for ( CVCPermission field : fields )
      {
        if (field == CVCPermission.AUT_INSTALL_QUALIFIED_CERTIFICATE)
        {
          SelectResult app = select.evaluate(transmitResult, new int[]{position++});
          if (app.isSelected())
          {
            SelectResult file = selectFile.evaluate(transmitResult, new int[]{position++});
            if (file.isSelected())
            {
              ReadResult result = readFile.evaluate(transmitResult, new int[]{position++});
              if (!ArrayUtil.isNullOrEmpty(result.getFileContent()))
              {
                Map<String, byte[]> evalResult = null;
                try
                {
                  evalResult = NPAUtil.evaluateEFOD(result.getFileContent());
                }
                catch (IOException e)
                {
                  throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE, e.getMessage(), e);
                }
                this.fidEFCD = evalResult.get(NPAUtil.FID_EFCD);
                this.fidEFPrKD = evalResult.get(NPAUtil.FID_EFPRKD);
                this.fidCACert = evalResult.get(NPAUtil.FID_CACERT);
                this.fidCert = evalResult.get(NPAUtil.FID_CERT);
                this.prKID = evalResult.get(NPAUtil.PRK_ID);
                installQES = true;
                continue;
              }
            }
          }
          throw new ECardException(ResultMinor.KEY_KEY_GENERATION_NOT_POSSIBLE,
                                   "Could not read cryptographic information file from card");
        }
        else if ((field.getFID() == null || new BigInteger(Hex.parse(field.getFID())).intValue() >= 0x0117)
                 && (field.getSFID() == null || Hex.parse(field.getSFID())[0] >= 0x17))
        {
          // there is nothing we can read
          continue;
        }
        else
        {
          LOG.debug(parent.getLogPrefix() + "READ field" + field.getDataFieldName());

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
              LOG.debug(parent.getLogPrefix() + LOG_DATA + "Could not read file for "
                        + field.getDataFieldName());
            }
            else if (!ArrayUtil.isNullOrEmpty(result.getFileContent()) && result.getFileContent()[0] != 0x00)
            {
              EIDInfoResult value = getASN1Value(result, field.getDataFieldName());
              LOG.debug(parent.getLogPrefix() + LOG_DATA + field.getDataFieldName()
                        + "' added to eidInfoContainer.");
              setParentPut(EIDKeys.valueOf(field.getDataFieldName()), value);
            }
            else
            {
              LOG.debug(parent.getLogPrefix() + LOG_DATA + "No result (read) for file "
                        + field.getDataFieldName());
            }
          }
          else
          {
            setParentPut(EIDKeys.valueOf(field.getDataFieldName()), new EIDInfoResultNotOnChip());
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Could not select file for "
                      + field.getDataFieldName());
          }
        }
      }
      if (handleCommandWriteAttributeRequest(transmitResult, position))
      {
        state = SequenceState.READ_PROVIDED_ATTRIBUTES;
      }
      else if (this.installQES)
      {
        if (this.fidCACert == null || this.fidCert == null || this.prKID == null)
        {
          state = SequenceState.QES_READ_CIA;
        }
        else
        {
          state = SequenceState.QES_EXAMINE_FILES;
        }
      }
      else
      {
        state = SequenceState.TRANSMIT_DONE;
      }
    }
    return getTransmitRequest();
  }

  private Object handleReadProvidedAttributes(TransmitAPDUResult transmitResult) throws ECardException
  {
    int index = 0;
    if (this.canReadSpecificAttributes())
    {
      handleCommandReadSpecificAttributes(transmitResult, index);
      index += 2;
    }

    for ( CVCPermission field : fields )
    {
      if (((field.getFID() == null || new BigInteger(Hex.parse(field.getFID())).intValue() < 0x0117) && (field.getSFID() == null || Hex.parse(field.getSFID())[0] < 0x17))
          || checkParentPresent(EIDKeys.valueOf(field.getDataFieldName())))
      {
        // only handle generic attributes that have not been read
        continue;
      }
      else
      {
        LOG.debug(parent.getLogPrefix() + "READ field" + field.getDataFieldName());

        SelectResult file = null;
        boolean withoutSelect = false;
        if (field.getSFID() == null)
        {
          file = selectFile.evaluate(transmitResult, new int[]{index++});
        }
        else
        {
          withoutSelect = true;
        }

        if (withoutSelect || file.isSelected())
        {
          ReadResult result = readFile.evaluate(transmitResult, new int[]{index++});
          if (result.getThrowable() != null)
          {
            if (result.getThrowable() instanceof FileNotFoundException)
            {
              setParentPut(EIDKeys.valueOf(field.getDataFieldName()), new EIDInfoResultNotOnChip());
            }
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "Could not read file for "
                      + field.getDataFieldName());
          }
          else if (!ArrayUtil.isNullOrEmpty(result.getFileContent()) && result.getFileContent()[0] != 0x00)
          {
            EIDInfoResult value = getASN1Value(result, field.getDataFieldName());
            LOG.debug(parent.getLogPrefix() + LOG_DATA + field.getDataFieldName()
                      + "' added to eidInfoContainer.");
            setParentPut(EIDKeys.valueOf(field.getDataFieldName()), value);
          }
          else
          {
            LOG.debug(parent.getLogPrefix() + LOG_DATA + "No result (read) for file "
                      + field.getDataFieldName());
          }
        }
      }
    }

    if (this.installQES)
    {
      if (this.fidCACert == null || this.fidCert == null || this.prKID == null)
      {
        state = SequenceState.QES_READ_CIA;
      }
      else
      {
        state = SequenceState.QES_EXAMINE_FILES;
      }
    }
    else
    {
      state = SequenceState.TRANSMIT_DONE;
    }
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
                               "The age verification process fails: " + result.getThrowable(),
                               result.getThrowable());
    }
  }

  private void checkBlockingIdentification(byte[] id) throws ECardException
  {
    BlackListConnector connector = parent.getConnector();
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Got Blacklist connector");
    if (connector == null)
    {
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR, "No Blacklist connector available");
    }

    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Try check...");
    try
    {
      boolean documentValidityVerificationFailed = connector.contains(id);
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Check done");
      if (documentValidityVerificationFailed)
      {
        LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Found Card on BlackList");
        setParentClear();
        parent.getEIDInfoContainer().setStatus(EIDStatus.REVOKED);
      }
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Card not found on BlackList");
    }
    catch (IOException e)
    {
      LOG.error(parent.getLogPrefix() + LOG_COMMAND + "BlackList defect: " + e, e);
    }
    finally
    {
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Leave Blacklist connector usage");
    }
  }

  private void checkBlockingIdentification(RestrictedIdentificationResult result) throws ECardException
  {
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "check BlockingIdentification...");
    if (result.getThrowable() == null && result.getFirstID() != null)
    {
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Result from MCard ok");
      // Checking card for blacklist
      byte[] currentSectorSpecificID = result.getFirstID();
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "First ID OK");
      this.checkBlockingIdentification(currentSectorSpecificID);
    }
    else
    {
      LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Exception!!!");
      if (result.getThrowable() != null)
      {
        throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                                 "Blocking identification verification failed: " + result.getThrowable());
      }
      throw new ECardException(ResultMinor.COMMON_INTERNAL_ERROR,
                               "Blocking identification verification failed: "
                                 + "Result contains no ID to use");
    }
    LOG.debug(parent.getLogPrefix() + LOG_COMMAND + "Leave method");
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
                               "Community affiliation process fails: " + result.getThrowable(),
                               result.getThrowable());
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
        LOG.error(parent.getLogPrefix() + "[SERVER] Document Validity negative");
        LOG.debug(parent.getLogPrefix() + "  Response > Create Transmit failed (DocumentValidity): "
                  + result.getData().toString());
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

  private boolean checkParentPresent(EIDKeys key)
  {
    return parent.getEIDInfoContainer().getInfoMap().get(key) != null;
  }

  /**
   * Method to set the checks that should be done on card
   */
  private void setVerificationStates(List<CVCPermission> fieldList)
  {
    // sort fields so that AUT_INSTALL_QUALIFIED_CERTIFIACTE is last if present
    if (fieldList.remove(CVCPermission.AUT_INSTALL_QUALIFIED_CERTIFICATE))
    {
      fieldList.add(CVCPermission.AUT_INSTALL_QUALIFIED_CERTIFICATE);
    }
    this.fields = fieldList;

    // Initialize the verification list
    verifications = new ArrayList<>();
    try
    {
      if (fieldList.remove(CVCPermission.AUT_SF_PSA) || fieldList.remove(CVCPermission.AUT_PSA)
          || this.parent.getEACFinal().getCaData().getCaInfo().getVersion() == 3)
      {
        verifications.add(VerificationCommand.PSEUDONYMOUS_SIGNATURE_AUTHENTICATION);
      }
      // if we do not use CA version 3, we must perform blocking identification (in CA v3 it is done via PSA)
      if (this.parent.getEACFinal().getCaData().getCaInfo().getVersion() != 3)
      {
        verifications.add(VerificationCommand.BLOCKING_IDENTIFICATION);
      }
    }
    catch (IOException e)
    {
      verifications.add(VerificationCommand.BLOCKING_IDENTIFICATION);
    }

    // Always check for document validity
    verifications.add(VerificationCommand.DOCUMENT_VALIDITY);

    if (this.fields.remove(CVCPermission.AUT_AGE_VERIFICATION)
        || this.fields.remove(CVCPermission.AUT_SF_AGE_VERIFICATION))
    {
      verifications.add(VerificationCommand.AGE_VERIFICATION);
      this.fields.remove(CVCPermission.AUT_SF_AGE_VERIFICATION);
    }
    if (this.fields.remove(CVCPermission.AUT_RESTRICTED_IDENTIFICATION)
        || this.fields.remove(CVCPermission.AUT_SF_RESTRICTED_IDENTIFICATION))
    {
      verifications.add(VerificationCommand.RESTRICTED_IDENTIFICATION);
      this.fields.remove(CVCPermission.AUT_SF_RESTRICTED_IDENTIFICATION);
    }
    if (this.fields.remove(CVCPermission.AUT_MUNICIPALITY_ID_VERIFICATION)
        || this.fields.remove(CVCPermission.AUT_SF_MUNICIPALITY_ID_VERIFICATION))
    {
      verifications.add(VerificationCommand.MUNICIPALITY_ID_VERIFICATION);
      this.fields.remove(CVCPermission.AUT_SF_MUNICIPALITY_ID_VERIFICATION);
    }
    if (this.fields.remove(CVCPermission.AUT_SF_PSC))
    {
      verifications.add(VerificationCommand.PSEUDONYMOUS_SIGNATURE_CREDENTIALS);
    }
    if (this.fields.remove(CVCPermission.AUT_SF_PSM))
    {
      verifications.add(VerificationCommand.PSEUDONYMOUS_SIGNATURE_MESSAGE);
    }

    // Output which checks are done
    StringBuilder debug = new StringBuilder(LOG_COMMAND + "VerificationStates set - Checks to be done: \n");
    verifications.stream().forEach(s -> debug.append("    o " + s.name() + "\n"));
    LOG.debug(parent.getLogPrefix() + debug.toString());
  }

  private boolean canReadSpecificAttributes()
  {
    return this.fields.contains(CVCPermission.AUT_READ_SPEC_ATT) && this.specificAttributesToRead != null
           && !this.specificAttributesToRead.isEmpty();
  }
}
