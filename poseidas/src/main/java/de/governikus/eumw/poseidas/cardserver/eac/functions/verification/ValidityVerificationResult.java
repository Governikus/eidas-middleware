/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.verification;

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;


/**
 * Implementation of DocumentValidityVerification output parameter.
 *
 * @see ValidityFunction
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ValidityVerificationResult extends AbstractResult<Boolean> implements FunctionResult<Boolean>
{

  /**
   * Constructor.
   *
   * @param b boolean result
   */
  public ValidityVerificationResult(Boolean b)
  {
    super(b);
  }

  /**
   * Constructor.
   *
   * @param throwable Throwable
   */
  public ValidityVerificationResult(Throwable throwable)
  {
    super(false, throwable);
  }
}
