/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.select;

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.FileParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.Read;


/**
 * Implementation of Read output parameter.
 *
 * @see Read
 * @see FileParameter
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class SelectResult extends AbstractResult<Boolean> implements FunctionResult<Boolean>
{

  private byte[] fcp = null;

  /**
   * Constructor.
   *
   * @param throwable throwable in case of errors
   */
  SelectResult(Throwable throwable)
  {
    super(throwable != null ? Boolean.FALSE : Boolean.TRUE, throwable);
  }

  /**
   * Constructor.
   *
   * @param selected <code>true</code> for successful, otherwise <code>false</code>
   */
  SelectResult(Boolean selected)
  {
    this(selected, null);
  }

  /**
   * Constructor.
   *
   * @param selected <code>true</code> for successful, otherwise <code>false</code>
   * @param fcp file control parameters
   */
  SelectResult(Boolean selected, byte[] fcp)
  {
    super(selected);
    this.fcp = fcp;
  }

  /**
   * Checks file or application successful selected.
   *
   * @return <code>true</code> if successful selected otherwise <code>false</code>
   */
  public boolean isSelected()
  {
    return super.getData().booleanValue();
  }

  /**
   * Gets file control parameters (only available if requested upon selection).
   *
   * @return file control parameters
   */
  public byte[] getFCP()
  {
    return this.fcp;
  }
}
