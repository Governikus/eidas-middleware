/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age;

import javax.smartcardio.CommandAPDU;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.impl.AbstractValidityFunction;


/**
 * Implementation of AgeVerification - verifies age.
 *
 * @see AgeVerificationParameter
 * @see ValidityVerificationResult
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class AgeVerification extends AbstractValidityFunction<AgeVerificationParameter> implements
  FunctionStep<AgeVerificationParameter, ValidityVerificationResult>, TransmitCommandCreator<AgeVerificationParameter>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public AgeVerification(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  protected CommandAPDU getVerifyCommand()
  {
    // verify mit OID Age Verification - 03110 - A.6.5.2, S.64
    return new CommandAPDU(Hex.parse("802080000b" + "0609" + "04007f000703010401"));
  }

}
