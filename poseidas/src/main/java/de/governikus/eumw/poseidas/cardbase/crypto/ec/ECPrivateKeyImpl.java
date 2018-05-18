/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.ec;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;


/**
 * Implementation of {@link ECPrivateKey} as substitution of SUN implementation supporting only SUN known
 * curves.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ECPrivateKeyImpl implements ECPrivateKey
{

  /**
   * Serial version UID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Private value S.
   */
  private final BigInteger s;

  /**
   * Domain parameters. Note: we have inherited {@link Serializable} through {@link ECPrivateKey} but would
   * run into errors serializing {@link ECParameterSpec} so we declare the fields transient as we do not need
   * to serialize instances of this class.
   */
  private final transient ECParameterSpec spec;

  /**
   * Constructor.
   * 
   * @param s private value S
   * @param spec curve specification
   */
  ECPrivateKeyImpl(BigInteger s, ECParameterSpec spec)
  {
    super();
    this.s = s;
    this.spec = spec;
  }

  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    throw new UnsupportedOperationException();
  }

  /** {@inheritDoc} */
  @Override
  public String getFormat()
  {
    throw new UnsupportedOperationException();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getEncoded()
  {
    throw new UnsupportedOperationException();
  }

  /** {@inheritDoc} */
  @Override
  public ECParameterSpec getParams()
  {
    return this.spec;
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getS()
  {
    return this.s;
  }
}
