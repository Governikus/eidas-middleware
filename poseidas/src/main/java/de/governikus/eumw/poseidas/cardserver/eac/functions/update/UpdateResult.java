/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.update;

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;


/**
 * Implementation of update output.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class UpdateResult extends AbstractResult<Boolean> implements FunctionResult<Boolean>
{

  /**
   * Constructor.
   * 
   * @param throwable throwable in case of errors
   */
  UpdateResult(Throwable throwable)
  {
    super(throwable != null ? Boolean.FALSE : Boolean.TRUE, throwable);
  }

  /**
   * Constructor.
   * 
   * @param written <code>true</code> for success, <code>false</code> otherwise
   */
  UpdateResult(Boolean written)
  {
    super(written);
  }

  /**
   * Checks file successfully written.
   * 
   * @return <code>true</code> if successfully written, <code>false</code> otherwise.
   */
  public boolean isWritten()
  {
    return super.getData().booleanValue();
  }
}
