/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.impl;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionStep;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDU;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.ValidityVerificationResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.age.AgeVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.community.CommunityIDVerification;
import de.governikus.eumw.poseidas.cardserver.eac.functions.verification.documentValidity.DocumentValidityVerification;


/**
 * Abstract implementation of any server related Connector for execution of any validity check card function.
 *
 * @param <R> type of result
 * @see FunctionParameter
 * @see ValidityVerificationResult
 * @see DocumentValidityVerification
 * @see AgeVerification
 * @see CommunityIDVerification
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public abstract class AbstractFunctionStep<S extends FunctionParameter, R extends FunctionResult<?>>
  implements FunctionStep<S, R>
{

  /**
   * {@link TransmitAPDU} instance, protected so that subclasses can use it
   */
  protected TransmitAPDU transmit = null;

  /**
   * Constructor with transmit.
   *
   * @param transmit transmit, <code>null</code> not permitted
   * @throws IllegalArgumentException if transmit <code>null</code>
   */
  public AbstractFunctionStep(TransmitAPDU transmit)
  {
    super();
    AssertUtil.notNull(transmit, "TransmitAPDU");
    this.transmit = transmit;
  }
}
