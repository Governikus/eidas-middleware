/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.mac;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;



/**
 * Interface for CMAC implementations.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface CMAC
{

  /**
   * The actual MAC calculation.
   * 
   * @param message message, <code>null</code> not permitted, empty permitted
   * @param byteLength requested length of MAC (bytes), must be more than 0
   * @return MAC
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws IllegalArgumentException if message <code>null</code> or byteLength less than 1
   */
  public abstract byte[] mac(byte[] message, int byteLength) throws IllegalBlockSizeException,
    BadPaddingException;

}
