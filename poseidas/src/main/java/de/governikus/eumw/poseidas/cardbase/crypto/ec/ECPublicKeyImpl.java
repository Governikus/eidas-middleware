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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;


/**
 * Implementation of {@link ECPublicKey} as substitution of SUN implementation supporting only SUN known
 * curves.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ECPublicKeyImpl implements ECPublicKey
{

  /**
   * Serial version UID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Public point W. Note: we have inherited {@link Serializable} through {@link ECPublicKey} but would run
   * into errors serializing {@link ECPoint} and {@link ECParameterSpec} so we declare the fields transient as
   * we do not need to serialize instances of this class.
   */
  private final transient ECPoint w;

  /**
   * Domain parameters. Note: we have inherited {@link Serializable} through {@link ECPublicKey} but would run
   * into errors serializing {@link ECPoint} and {@link ECParameterSpec} so we declare the fields transient as
   * we do not need to serialize instances of this class.
   */
  private final transient ECParameterSpec spec;

  /**
   * Constructor.
   * 
   * @param w public point W
   * @param spec curve specification
   */
  public ECPublicKeyImpl(ECPoint w, ECParameterSpec spec)
  {
    super();
    if (!ECMath.isPointOnCurve(w, spec))
    {
      throw new IllegalArgumentException("check failed: point is not on curve");
    }
    this.w = w;
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
    int trimLen = spec.getCurve().getField().getFieldSize() / 8;

    ASN1 version = new ASN1(0x02, new byte[]{0x01});

    ASN1 primeOID = new ASN1(0x06, new byte[]{0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x01, 0x01});
    ASN1 prime = new ASN1(0x02, ((ECFieldFp)spec.getCurve().getField()).getP().toByteArray());
    ASN1 primeSeq = new ASN1(0x30, ByteUtil.combine(primeOID.getEncoded(), prime.getEncoded()));

    ASN1 curveA = new ASN1(0x04, ByteUtil.trimByteArray(spec.getCurve().getA().toByteArray(), trimLen));
    ASN1 curveB = new ASN1(0x04, ByteUtil.trimByteArray(spec.getCurve().getB().toByteArray(), trimLen));
    ASN1 curveSeq = new ASN1(0x30, ByteUtil.combine(curveA.getEncoded(), curveB.getEncoded()));

    ASN1 generator = new ASN1(0x04, ByteUtil.combine(new byte[][]{
                                                                  new byte[]{0x04},
                                                                  ByteUtil.trimByteArray(spec.getGenerator()
                                                                                             .getAffineX()
                                                                                             .toByteArray(),
                                                                                         trimLen),
                                                                  ByteUtil.trimByteArray(spec.getGenerator()
                                                                                             .getAffineY()
                                                                                             .toByteArray(),
                                                                                         trimLen)}));
    ASN1 order = new ASN1(0x02, spec.getOrder().toByteArray());
    ASN1 cofactor = new ASN1(0x02, new byte[]{(byte)spec.getCofactor()});

    ASN1 innerDomParamSeq = new ASN1(0x30, ByteUtil.combine(new byte[][]{version.getEncoded(),
                                                                         primeSeq.getEncoded(),
                                                                         curveSeq.getEncoded(),
                                                                         generator.getEncoded(),
                                                                         order.getEncoded(),
                                                                         cofactor.getEncoded()}));

    ASN1 oid = new ASN1(0x06, new byte[]{0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x02, 0x01});
    ASN1 domParamSeq = new ASN1(0x30, ByteUtil.combine(oid.getEncoded(), innerDomParamSeq.getEncoded()));

    byte[] ptBytes = ByteUtil.combine(new byte[][]{
                                                   new byte[]{0x00, 0x04},
                                                   ByteUtil.trimByteArray(w.getAffineX().toByteArray(),
                                                                          trimLen),
                                                   ByteUtil.trimByteArray(w.getAffineY().toByteArray(),
                                                                          trimLen)});
    ASN1 pt = new ASN1(0x03, ptBytes);
    ASN1 complete = new ASN1(0x30, ByteUtil.combine(domParamSeq.getEncoded(), pt.getEncoded()));
    return complete.getEncoded();
  }

  /** {@inheritDoc} */
  @Override
  public ECParameterSpec getParams()
  {
    return this.spec;
  }

  /** {@inheritDoc} */
  @Override
  public ECPoint getW()
  {
    return this.w;
  }
}
