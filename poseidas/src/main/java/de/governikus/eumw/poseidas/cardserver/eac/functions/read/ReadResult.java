/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.read;

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.impl.FileParameter;


/**
 * Implementation of Read output parameter.
 *
 * @see Read
 * @see FileParameter
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ReadResult extends AbstractResult<byte[]> implements FunctionResult<byte[]>
{

  /**
   * Constructor.
   *
   * @param throwable throwable in case of errors
   */
  ReadResult(Throwable throwable)
  {
    super(throwable);
  }

  /**
   * Constructor.
   *
   * @param fileContent file content
   */
  ReadResult(byte[] fileContent)
  {
    super(fileContent);
  }

  /**
   * Gets file content.
   *
   * @return file content as byte-array, maybe <code>null</code> or empty in case of errors
   */
  public byte[] getFileContent()
  {
    return super.getData();
  }

}
