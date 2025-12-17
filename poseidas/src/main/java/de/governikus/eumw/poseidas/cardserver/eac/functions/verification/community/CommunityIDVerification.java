/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community;

import javax.smartcardio.CommandAPDU;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.TransmitCommandCreator;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.impl.AbstractValidityFunction;


/**
 * Implementation of CommunityIDVerification - verifies community.
 *
 * @see CommunityIDVerificationParameter
 * @see ValidityVerificationResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CommunityIDVerification extends AbstractValidityFunction<CommunityIDVerificationParameter>
  implements FunctionStep<CommunityIDVerificationParameter, ValidityVerificationResult>,
  TransmitCommandCreator<CommunityIDVerificationParameter>
{

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   */
  public CommunityIDVerification(TransmitAPDU transmit)
  {
    super(transmit);
  }

  /** {@inheritDoc} */
  @Override
  protected CommandAPDU getVerifyCommand()
  {
    // verify mit OID Community ID Verification - 03110 - A.6.5.4, S.64
    return new CommandAPDU(Hex.parse("802080000b" + "0609" + "04007f000703010403"));
  }

}
