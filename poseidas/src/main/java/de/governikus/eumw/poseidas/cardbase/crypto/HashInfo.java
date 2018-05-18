/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto;

import java.security.Security;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;




/**
 * Interface for hash related informations.
 * 
 * @see HashAlgorithm
 * @see HashAlgorithmEnum
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface HashInfo
{

  /**
   * Gets name of algorithm as used at {@link Security}.
   * 
   * @return name
   */
  public String getName();

  /**
   * Gets length of hash.
   * 
   * @return length of hash
   */
  public int getHashLength();

  /**
   * Gets OID of algorithm as String.
   * 
   * @return OID
   */
  public String getOIDString();

  /**
   * Gets OID of algorithm.
   * 
   * @return OID
   */
  public OID getOID();

  /**
   * Gets encoded representation of hash.
   * 
   * @return byte[]-array representation
   */
  public byte[] getEncoded();

  /**
   * Get OID as byte[]-array.
   * 
   * @return OID as byte[]-array
   */
  public byte[] getOIDValue();

}
