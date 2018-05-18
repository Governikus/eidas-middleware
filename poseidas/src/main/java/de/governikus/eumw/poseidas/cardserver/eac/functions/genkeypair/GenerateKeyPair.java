/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.genkeypair;

import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardserver.eac.InputAPDUInfoTypeUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitResultEvaluator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.AbstractFunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Function for generating signature key pair on card.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class GenerateKeyPair extends AbstractFunctionStep<GenerateKeyPairParameter, GenerateKeyPairResult>
  implements FunctionStep<GenerateKeyPairParameter, GenerateKeyPairResult>,
  TransmitCommandCreator<GenerateKeyPairParameter>, TransmitResultEvaluator<GenerateKeyPairResult>
{

  /**
   * Constructor.
   * 
   * @param throwable throwable in case of errors
   */
  public GenerateKeyPair(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  public int getMinimumCount()
  {
    return 1;
  }

  /** {@inheritDoc} */
  @Override
  public int getMaximumCount()
  {
    return 1;
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(GenerateKeyPairParameter parameter)
  {
    return this.create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public List<InputAPDUInfoType> create(GenerateKeyPairParameter parameter,
                                        List<ResponseAPDU> acceptedResponseList)
  {
    ASN1 keyRef = new ASN1(new byte[]{(byte)0x84}, parameter.getKeyID());
    ASN1 dst = new ASN1(new byte[]{(byte)0xb6}, keyRef.getEncoded());
    CommandAPDU command = new CommandAPDU(0x00, 0x47, 0x82, 0x00, dst.getEncoded(), 0x10000);
    return InputAPDUInfoTypeUtil.create(command, acceptedResponseList);
  }

  /** {@inheritDoc} */
  @Override
  public Transmit parameterStep(GenerateKeyPairParameter parameter, byte[] sht)
  {
    AssertUtil.notNull(sht, "slot handle");
    List<InputAPDUInfoType> listTransmitCommand = create(parameter, null);
    if (listTransmitCommand == null)
    {
      return null;
    }
    TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

    Transmit securedTransmitParameter = super.transmit.parameterStep(tap, sht);
    return securedTransmitParameter;
  }

  /** {@inheritDoc} */
  @Override
  public GenerateKeyPairResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, null);
  }

  /** {@inheritDoc} */
  @Override
  public GenerateKeyPairResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult,
                                                                  responseIndices,
                                                                  getMinimumCount(),
                                                                  getMaximumCount());
    if (transmitResult.getThrowable() != null)
    {
      return new GenerateKeyPairResult(transmitResult.getThrowable());
    }
    GenerateKeyPairResult gkpResult = new GenerateKeyPairResult(
                                                                new ResponseAPDU(
                                                                                 transmitResult.getData()
                                                                                               .getOutputAPDU()
                                                                                               .get(responseIndices[0])).getData());
    return gkpResult;
  }
}
