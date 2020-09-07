/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.sm;

import java.math.BigInteger;

import javax.crypto.SecretKey;

import de.governikus.eumw.poseidas.cardbase.crypto.sm.AESEncSSCIvParameterSpec;


public class BatchAESEncSSCIvParameterSpec extends AESEncSSCIvParameterSpec
{

  // marker
  private BigInteger marker = null;

  public BatchAESEncSSCIvParameterSpec(byte[] ssc, SecretKey keyEnc)
  {
    super(ssc, keyEnc);
  }


  void mark()
  {
    this.marker = this.ssc;
  }

  void reset()
  {
    this.ssc = this.marker;
    createIV();
  }
}
