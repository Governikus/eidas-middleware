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

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;


/**
 * Result of key generation.
 * 
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public class GenerateKeyPairResult extends AbstractResult<byte[]> implements FunctionResult<byte[]>
{

  /**
   * Constructor.
   * 
   * @param throwable throwable in case of errors
   */
  GenerateKeyPairResult(Throwable throwable)
  {
    super(throwable);
  }

  /**
   * Constructor.
   * 
   * @param keyData public key data
   */
  GenerateKeyPairResult(byte[] keyData)
  {
    super(keyData);
  }

  /**
   * Gets public key data.
   * 
   * @return public key data as byte-array
   */
  public byte[] getKeyData()
  {
    return super.getData();
  }
}
