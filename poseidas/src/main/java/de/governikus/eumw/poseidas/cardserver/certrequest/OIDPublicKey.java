/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.certrequest;

import java.io.IOException;
import java.security.Key;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Interface for enhanced public key related to an OID.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface OIDPublicKey
{

  /**
   * Gets public key related OID.
   * 
   * @return OID
   */
  public abstract OID getOID();

  /**
   * Get encoded public key including related OID.
   * 
   * @return encoded public key
   * @throws IOException
   * @throws IllegalArgumentException
   * @see Key#getEncoded()
   */
  public abstract byte[] getEncodedWithOID() throws IOException;

}
