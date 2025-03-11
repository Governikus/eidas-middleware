/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.verification.impl;

import java.util.Arrays;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.card.SmartCardCodeConstants;
import de.governikus.eumw.poseidas.cardserver.eac.InputAPDUInfoTypeUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitResultEvaluator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.AbstractFunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerification;
import iso.std.iso_iec._24727.tech.schema.InputAPDUInfoType;
import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Abstract implementation of any server related Connector for execution of any validity check card function.
 *
 * @param <T> type of parameter
 * @see FunctionParameter
 * @see ValidityVerificationResult
 * @see DocumentValidityVerification
 * @see AgeVerification
 * @see CommunityIDVerification
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public abstract class AbstractValidityFunction<T extends FunctionParameter>
  extends AbstractFunctionStep<T, ValidityVerificationResult> implements FunctionStep<T, ValidityVerificationResult>,
  TransmitCommandCreator<T>, TransmitResultEvaluator<ValidityVerificationResult>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public AbstractValidityFunction(TransmitAPDU transmit)
  {
    super(transmit);
    AssertUtil.notNull(transmit, "TransmitAPDU");
  }

  /** {@inheritDoc} */
  @Override
  public final ValidityVerificationResult resultStep(TransmitResponse result)
  {
    AssertUtil.notNull(result, "result");
    TransmitAPDUResult unsecuredResult = super.transmit.resultStep(result);
    return evaluate(unsecuredResult, null);
  }

  /** {@inheritDoc} */
  @Override
  public final Transmit parameterStep(T parameter, byte[] sht)
  {
    AssertUtil.notNull(sht, "slot handle");
    CommandAPDU command = this.getVerifyCommand();
    List<InputAPDUInfoType> listTransmitCommand = InputAPDUInfoTypeUtil.create(Arrays.asList(command));

    TransmitAPDUParameter tap = new TransmitAPDUParameter(listTransmitCommand);

    return super.transmit.parameterStep(tap, sht);
  }

  /**
   * Gets {@link CommandAPDU} for verify command.
   *
   * @return command
   */
  protected abstract CommandAPDU getVerifyCommand();

  /** {@inheritDoc} */
  @Override
  public final List<InputAPDUInfoType> create(T parameter)
  {
    return create(parameter, null);
  }

  /** {@inheritDoc} */
  @Override
  public final List<InputAPDUInfoType> create(T parameter, List<ResponseAPDU> acceptedResponseList)
  {
    return InputAPDUInfoTypeUtil.create(this.getVerifyCommand(), acceptedResponseList);
  }

  /** {@inheritDoc} */
  @Override
  public final ValidityVerificationResult evaluate(TransmitAPDUResult transmitResult, int[] responseIndices)
  {
    if (transmitResult.getThrowable() != null)
    {
      return new ValidityVerificationResult(transmitResult.getThrowable());
    }
    responseIndices = TransmitResultEvaluator.Util.checkArguments(transmitResult, responseIndices);

    int returnCode = new ResponseAPDU(transmitResult.getData().getOutputAPDU().get(responseIndices[0])).getSW();
    ValidityVerificationResult vvResult;
    if (returnCode == SmartCardCodeConstants.SUCCESSFULLY_PROCESSED)
    {
      vvResult = new ValidityVerificationResult(true);
    }
    else if (returnCode == SmartCardCodeConstants.REFERENCED_DATA_NOT_FOUND)
    {
      vvResult = new ValidityVerificationResult(new IllegalStateException("referenced data not found"));
    }
    else if (returnCode == SmartCardCodeConstants.SECURITY_STATUS_NOT_SATISFIED)
    {
      vvResult = new ValidityVerificationResult(new IllegalStateException("terminal not authorized to perform verification"));
    }
    else
    {
      vvResult = new ValidityVerificationResult(false);
    }
    return vvResult;
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
}
