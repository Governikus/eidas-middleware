/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.sm.BatchSecureMessaging;
import de.governikus.eumw.poseidas.cardserver.sm.CardCommunication;
import de.governikus.eumw.poseidas.cardserver.sm.CardCommunicationImpl;
import de.governikus.eumw.poseidas.ecardcore.core.ECardException;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Implementation of TransmitAPDU function.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class TransmitAPDU implements FunctionStep<TransmitAPDUParameter, TransmitAPDUResult>
{

  private static final Log LOG = LogFactory.getLog(TransmitAPDU.class);

  /**
   * Secure Messaging instance.
   */
  private BatchSecureMessaging sm = null;

  /**
   * Card communication instance.
   */
  private CardCommunication cc = null;


  /**
   * Constructor.
   *
   * @param sm layer of secure messaging
   */
  public TransmitAPDU(BatchSecureMessaging sm)
  {
    super();
    AssertUtil.notNull(sm, "Secure Messaging");
    this.sm = sm;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized Transmit parameterStep(TransmitAPDUParameter parameter, byte[] sht)
  {
    AssertUtil.notNull(parameter, "parameter");
    AssertUtil.notNull(sht, "slot handle");
    if (this.cc != null)
    {
      throw new IllegalStateException("cc already initialized from another parameterStep");
    }

    List<CommandAPDU> commands = new ArrayList<>();
    for ( InputAPDUInfoType inputAPDU : parameter.getCommandList() )
    {
      CommandAPDU cmd = new CommandAPDU(inputAPDU.getInputAPDU());
      LOG.debug("Command to be sent to card:\n" + Hex.dump(cmd.getBytes()));
      commands.add(cmd);
    }
    this.cc = new CardCommunicationImpl(commands.toArray(new CommandAPDU[0]));
    this.sm.toCard(this.cc);

    List<InputAPDUInfoType> resultList = new ArrayList<>();
    CommandAPDU[] securedCommands = this.cc.getEncryptedCommands();
    if (!ArrayUtil.isNullOrEmpty(securedCommands))
    {
      for ( int i = 0 ; i < securedCommands.length ; i++ )
      {
        InputAPDUInfoType iait = new InputAPDUInfoType();
        iait.setInputAPDU(securedCommands[i].getBytes());
        iait.getAcceptableStatusCode().addAll(parameter.getCommandList().get(i).getAcceptableStatusCode());
        resultList.add(iait);
      }
    }
    Transmit ret = new Transmit();
    ret.getInputAPDUInfo().addAll(resultList);
    ret.setSlotHandle(sht);
    return ret;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized TransmitAPDUResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    if (this.cc == null)
    {
      throw new IllegalStateException("cc not initialized from parameterStep");
    }

    try
    {
      List<ResponseAPDU> rList = new ArrayList<>();
      for ( byte[] rBytes : result.getOutputAPDU() )
      {
        rList.add(new ResponseAPDU(rBytes));
      }
      this.cc.setEncryptedResponses(rList.toArray(new ResponseAPDU[0]));
      this.sm.fromCard(this.cc);

      List<byte[]> rByteList = new ArrayList<>();
      ResponseAPDU[] plainResponses = this.cc.getPlaintextResponses();
      if (!ArrayUtil.isNullOrEmpty(plainResponses))
      {
        for ( ResponseAPDU r : plainResponses )
        {
          byte[] respBytes = r.getBytes();
          LOG.debug("Response from card:\n" + Hex.dump(respBytes));
          rByteList.add(respBytes);
        }
      }

      TransmitResponse decryptedResult = new TransmitResponse();
      decryptedResult.getOutputAPDU().addAll(rByteList);
      decryptedResult.setResult(result.getResult());

      if (this.cc.getThrowable() != null)
      {
        return new TransmitAPDUResult(decryptedResult, this.cc.getThrowable());
      }
      if (!ResultMajor.OK.toString().equals(result.getResult().getResultMajor()))
      {
        return new TransmitAPDUResult(decryptedResult, new ECardException(result.getResult()));
      }
      else
      {
        return new TransmitAPDUResult(decryptedResult);
      }
    }
    finally
    {
      this.cc = null;
    }
  }
}
