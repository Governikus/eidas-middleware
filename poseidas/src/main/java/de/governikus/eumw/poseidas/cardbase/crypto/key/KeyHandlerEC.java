/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.key;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.DomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECMath;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECPublicKeyImpl;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECUtil;


/**
 * Implementation of {@link KeyHandler} for EC keys (Fp variant only, F2m currently not used in nPA context).
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class KeyHandlerEC implements KeyHandler
{

  private static final String ARGUMENT_PUB_MUST_BE_AN_EC_PUBLIC_KEY = "argument pub must be an ECPublicKey";

  /**
   * Size of field (in bytes).
   */
  protected final int fieldSize;

  /**
   * Constructor.
   *
   * @param parameter field size (from domain parameters, in bytes), must be at least 1
   * @throws IllegalArgumentException if fieldSize zero or negative
   */
  public KeyHandlerEC(int parameter)
  {
    super();
    AssertUtil.greaterEquals(parameter, 1, "field size");
    this.fieldSize = parameter;
  }

  /** {@inheritDoc} */
  @Override
  public KeyPair generateKeyPair(DomainParameterInfo params)
    throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    AssertUtil.notNull(params, "domain parameter info");
    ECParameterSpec paramSpec = ECUtil.parameterSpecFromDomainParameters(params);
    return generateKeyPair(paramSpec);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: spec must be of type java.security.spec.ECParameterSpec
   * </p>
   */
  // to be changed when SunEC provider can be used for generation
  @Override
  public KeyPair generateKeyPair(AlgorithmParameterSpec spec)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    AssertUtil.notNull(spec, "parameter spec");
    if (!(spec instanceof ECParameterSpec))
    {
      throw new IllegalArgumentException("argument spec must be an ECParameterSpec");
    }
    return ECMath.generateKeyPair((ECParameterSpec)spec);
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey buildKeyFromBytes(DomainParameterInfo params, byte[] keyBytes) throws IOException
  {
    AssertUtil.notNull(params, "domain parameter info");
    AssertUtil.notNullOrEmpty(keyBytes, "key bytes");

    ECParameterSpec paramSpec = ECUtil.parameterSpecFromDomainParameters(params);
    return this.buildKeyFromBytes(paramSpec, keyBytes);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: spec must be of type java.security.spec.ECParameterSpec
   * </p>
   */
  @Override
  public PublicKey buildKeyFromBytes(AlgorithmParameterSpec spec, byte[] keyBytes)
  {
    AssertUtil.notNull(spec, "parameter spec");
    AssertUtil.notNullOrEmpty(keyBytes, "key bytes");
    if (!(spec instanceof ECParameterSpec))
    {
      throw new IllegalArgumentException("argument paramSpec must be an ECParameterSpec");
    }

    ECPoint point = ECMath.pointFromBytes(keyBytes, this.fieldSize);
    return new ECPublicKeyImpl(point, (ECParameterSpec)spec);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: priv must be of type java.security.interfaces.ECPrivateKey <br/>
   * pub must be of type java.security.interfaces.ECPublicKey
   * </p>
   */
  @Override
  public byte[] calculateSharedSecret(PrivateKey priv, PublicKey pub)
  {
    AssertUtil.notNull(priv, "private key");
    AssertUtil.notNull(pub, "public key");
    if (!(priv instanceof ECPrivateKey))
    {
      throw new IllegalArgumentException("argument priv must be an ECPrivateKey");
    }
    if (!(pub instanceof ECPublicKey))
    {
      throw new IllegalArgumentException(ARGUMENT_PUB_MUST_BE_AN_EC_PUBLIC_KEY);
    }

    ECPoint sharedPoint = ECMath.calcSharedSecret((ECPrivateKey)priv, (ECPublicKey)pub);
    return ByteUtil.trimByteArray(sharedPoint.getAffineX().toByteArray(), this.fieldSize);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: key must be of type java.security.interfaces.ECPublicKey
   * </p>
   */
  @Override
  public byte[] ephemeralKeyBytes(PublicKey key)
  {
    AssertUtil.notNull(key, "public key");
    if (!(key instanceof ECPublicKey))
    {
      throw new IllegalArgumentException(ARGUMENT_PUB_MUST_BE_AN_EC_PUBLIC_KEY);
    }
    return this.getEncoded(((ECPublicKey)key).getW());
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: key must be of type java.security.interfaces.ECPublicKey
   * </p>
   */
  @Override
  public byte[] convertPublicKey(PublicKey key, OID oid, boolean fullStructure) throws IOException
  {
    AssertUtil.notNull(key, "key");
    AssertUtil.notNull(oid, "OID");
    if (!(key instanceof ECPublicKey))
    {
      throw new IllegalArgumentException(ARGUMENT_PUB_MUST_BE_AN_EC_PUBLIC_KEY);
    }
    ECPublicKey sunKey = (ECPublicKey)key;

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(oid.getEncoded());
    if (fullStructure)
    {
      ASN1 primeModulus = new ASN1(0x81,
                                   ByteUtil.removeLeadingZero(((ECFieldFp)sunKey.getParams()
                                                                                .getCurve()
                                                                                .getField()).getP()
                                                                                            .toByteArray()));
      ASN1 firstCoefficient = new ASN1(0x82,
                                       ByteUtil.removeLeadingZero(sunKey.getParams()
                                                                        .getCurve()
                                                                        .getA()
                                                                        .toByteArray()));
      ASN1 secondCoefficient = new ASN1(0x83,
                                        ByteUtil.removeLeadingZero(sunKey.getParams()
                                                                         .getCurve()
                                                                         .getB()
                                                                         .toByteArray()));
      ASN1 basePoint = new ASN1(0x84, this.getEncoded(sunKey.getParams().getGenerator()));
      ASN1 orderOfBasePoint = new ASN1(0x85,
                                       ByteUtil.removeLeadingZero(sunKey.getParams()
                                                                        .getOrder()
                                                                        .toByteArray()));
      baos.write(primeModulus.getEncoded());
      baos.write(firstCoefficient.getEncoded());
      baos.write(secondCoefficient.getEncoded());
      baos.write(basePoint.getEncoded());
      baos.write(orderOfBasePoint.getEncoded());
    }
    ASN1 publicPoint = new ASN1(0x86, this.getEncoded(sunKey.getW()));
    baos.write(publicPoint.getEncoded());
    if (fullStructure)
    {
      ASN1 cofactor = new ASN1(0x87,
                               ByteUtil.removeLeadingZero(BigInteger.valueOf(sunKey.getParams().getCofactor())
                                                                    .toByteArray()));
      baos.write(cofactor.getEncoded());
    }
    return new ASN1(0x7f49, baos.toByteArray()).getEncoded();
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: key must be of type java.security.interfaces.ECPublicKey
   * </p>
   */
  @Override
  public byte[] compressKey(PublicKey key)
  {
    AssertUtil.notNull(key, "key");
    if (!(key instanceof ECPublicKey))
    {
      throw new IllegalArgumentException("argument key must be an ECPublicKey");
    }
    return ByteUtil.trimByteArray(((ECPublicKey)key).getW().getAffineX().toByteArray(), this.fieldSize);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] compressKey(byte[] keyBytes)
  {
    AssertUtil.notNullOrEmpty(keyBytes, "key");
    return ByteUtil.subbytes(keyBytes, 1, (keyBytes.length - 1) / 2 + 1);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Note: o must be of type java.security.spec.ECPoint
   * </p>
   */
  @Override
  public byte[] getEncoded(Object o)
  {
    AssertUtil.notNull(o, "EC point");
    if (!(o instanceof ECPoint))
    {
      throw new IllegalArgumentException("argument o must be an ECPoint");
    }
    byte[] result = ByteUtil.combine(new byte[]{0x04},
                                     ByteUtil.trimByteArray(((ECPoint)o).getAffineX().toByteArray(),
                                                            this.fieldSize));
    result = ByteUtil.combine(result,
                              ByteUtil.trimByteArray(((ECPoint)o).getAffineY().toByteArray(),
                                                     this.fieldSize));
    return result;
  }
}
