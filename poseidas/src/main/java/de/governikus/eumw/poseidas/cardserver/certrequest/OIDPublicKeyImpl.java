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
import java.security.PublicKey;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandler;


/**
 * Implementation of public key with OID.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @see KeyHandler
 */
public class OIDPublicKeyImpl implements PublicKey, OIDPublicKey
{

  private static final long serialVersionUID = 1L;

  private PublicKey publicKey = null;

  private OID oid = null;

  private KeyHandler kh = null;

  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return publicKey.getAlgorithm();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getEncoded()
  {
    return publicKey.getEncoded();
  }

  /** {@inheritDoc} */
  @Override
  public String getFormat()
  {
    return publicKey.getFormat();
  }

  /**
   * Constructor.
   * 
   * @param publicKey public key
   * @param kh key handler
   * @param oid OID
   */
  OIDPublicKeyImpl(PublicKey publicKey, KeyHandler kh, OID oid)
  {
    super();
    this.publicKey = publicKey;
    this.kh = kh;
    this.oid = oid;
  }

  /** {@inheritDoc} */
  @Override
  public OID getOID()
  {
    return this.oid;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getEncodedWithOID() throws IOException
  {
    return kh.convertPublicKey(this.publicKey, oid, true);
  }
}
