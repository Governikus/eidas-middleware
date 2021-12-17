/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.ec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Implementation of some EC calculations.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ECMath
{

  /**
   * Constructor
   */
  private ECMath()
  {
    super();
  }

  /**
   * Calculates shared secret as an {@link ECPoint}.
   *
   * @param priv own private key, <code>null</code> not permitted
   * @param pub received public key, <code>null</code> not permitted
   * @return shared secret as an {@link ECPoint}
   * @throws IllegalArgumentException if any argument <code>null</code>
   */
  public static ECPoint calcSharedSecret(ECPrivateKey priv, ECPublicKey pub)
  {
    AssertUtil.notNull(priv, "private key");
    AssertUtil.notNull(pub, "public key");

    BigInteger a = pub.getParams().getCurve().getA();
    BigInteger prime = ((ECFieldFp)pub.getParams().getCurve().getField()).getP();
    return multiplyECPoint(pub.getW(), priv.getS(), a, prime);
  }

  /**
   * Generates a KeyPair using given parameter spec.
   * <p>
   * </p>
   * Note: to be removed as soon as Java provides (usable) own implementation. This version is actually not
   * especially efficient.
   *
   * @param spec parameter specification, <code>null</code> not permitted
   * @return generated keypair
   * @throws IllegalArgumentException if spec <code>null</code>
   */
  public static KeyPair generateKeyPair(ECParameterSpec spec)
  {
    AssertUtil.notNull(spec, "spec");
    SecureRandom sr = new SecureRandom();
    BigInteger n = spec.getOrder();
    int nbl = n.bitLength();
    BigInteger d = null;
    do
    {
      d = new BigInteger(nbl, sr);
    }
    while (BigInteger.ZERO.equals(d) || d.compareTo(n) >= 0);
    ECPoint g = spec.getGenerator();
    ECPoint q = multiplyECPoint(g, d, spec.getCurve().getA(), ((ECFieldFp)spec.getCurve().getField()).getP());
    return new KeyPair(new ECPublicKeyImpl(q, spec), new ECPrivateKeyImpl(d, spec));
  }

  /**
   * Multiplies an {@link ECPoint} with a {@link BigInteger} factor.
   * <p>
   * </p>
   * Note: to be removed as soon as Java provides (usable) own implementation. This version is actually not
   * especially efficient.
   *
   * @param p point, <code>null</code> not permitted
   * @param factor factor, <code>null</code> not permitted, must be positive
   * @param a first coefficient (domain parameters), <code>null</code> not permitted
   * @param prime prime integer (domain parameters), <code>null</code> not permitted
   * @return result of multiplication
   * @throws IllegalArgumentException if any argument <code>null</code> or factor not positive
   */
  public static ECPoint multiplyECPoint(ECPoint p, BigInteger factor, BigInteger a, BigInteger prime)
  {
    AssertUtil.notNull(p, "point");
    AssertUtil.notNull(factor, "factor");
    AssertUtil.notNull(a, "first curve coefficient");
    AssertUtil.notNull(prime, "prime");
    if (factor.compareTo(BigInteger.valueOf(0)) <= 0)
    {
      throw new IllegalArgumentException("factor must be positive and not 0");
    }
    if (factor.equals(BigInteger.valueOf(1)))
    {
      return p;
    }
    ECPoint result = p;
    for ( int i = factor.bitLength() - 2 ; i >= 0 ; i-- )
    {
      result = doubleECPoint(result, a, prime);
      if (factor.testBit(i))
      {
        result = addECPoints(result, p, a, prime);
      }
    }
    return result;
  }

  /**
   * Doubles an {@link ECPoint}.
   * <p>
   * </p>
   * Note: to be removed as soon as Java provides own (usable) implementation.
   *
   * @param p point
   * @param a first coefficient (domain parameters)
   * @param prime prime integer (domain parameters)
   * @return result of doubling
   */
  private static ECPoint doubleECPoint(ECPoint p, BigInteger a, BigInteger prime)
  {
    BigInteger s = p.getAffineX()
                    .pow(2)
                    .multiply(BigInteger.valueOf(3))
                    .add(a)
                    .multiply(p.getAffineY().multiply(BigInteger.valueOf(2)).modInverse(prime))
                    .mod(prime);
    BigInteger x = s.pow(2).subtract(p.getAffineX().multiply(BigInteger.valueOf(2))).mod(prime);
    BigInteger y = p.getAffineY().negate().add(s.multiply(p.getAffineX().subtract(x))).mod(prime);
    return new ECPoint(x, y);
  }

  /**
   * Adds two {@link ECPoint}s.
   * <p>
   * </p>
   * Note: to be removed as soon as Java provides own (usable) implementation.
   *
   * @param p first point, <code>null</code> not permitted
   * @param q second point, <code>null</code> not permitted
   * @param a first coefficient (domain parameters), <code>null</code> not permitted
   * @param prime prime integer (domain parameters), <code>null</code> not permitted
   * @return result of addition
   * @throws IllegalArgumentException if any argument <code>null</code>
   */
  public static ECPoint addECPoints(ECPoint p, ECPoint q, BigInteger a, BigInteger prime)
  {
    AssertUtil.notNull(p, "first point");
    AssertUtil.notNull(q, "second point");
    AssertUtil.notNull(a, "first curve coefficient");
    AssertUtil.notNull(prime, "prime");
    if (p.equals(q))
    {
      return doubleECPoint(p, a, prime);
    }
    if (p.getAffineX().equals(q.getAffineX()) && p.getAffineY().equals(q.getAffineY().negate().mod(prime)))
    {
      return ECPoint.POINT_INFINITY;
    }
    BigInteger s = p.getAffineY()
                    .subtract(q.getAffineY())
                    .multiply(p.getAffineX().subtract(q.getAffineX()).modInverse(prime))
                    .mod(prime);

    BigInteger x = s.pow(2).subtract(p.getAffineX()).subtract(q.getAffineX()).mod(prime);
    BigInteger y = p.getAffineY().negate().add(s.multiply(p.getAffineX().subtract(x))).mod(prime);
    return new ECPoint(x, y);
  }

  /**
   * Generates {@link ECPoint} object from byte-array representation of EC point
   *
   * @param pointBytes EC point in byte-array representation, <code>null</code> or empty not permitted, length
   *          must be exactly one plus double fieldSize
   * @param fieldSize size of field (domain parameters) (in bytes), must be positive
   * @return generated {@link ECPoint} object
   * @throws IllegalArgumentException if pointBytes <code>null</code> or empty, length not matching
   *           requirement, or if fieldSize not positive
   */
  public static ECPoint pointFromBytes(byte[] pointBytes, int fieldSize)
  {
    AssertUtil.notNullOrEmpty(pointBytes, "bytes");
    AssertUtil.greaterEquals(fieldSize, 1, "field size");
    if (pointBytes.length != fieldSize * 2 + 1)
    {
      throw new IllegalArgumentException("length of array not matching");
    }
    BigInteger xCoord = new BigInteger(1, ByteUtil.subbytes(pointBytes, 1, fieldSize + 1));
    BigInteger yCoord = new BigInteger(1, ByteUtil.subbytes(pointBytes, 1 + fieldSize, pointBytes.length));
    return new ECPoint(xCoord, yCoord);
  }

  /**
   * Verifies EC signature. (Note: not tuned for efficiency, to be replaced as soon as Java provides own
   * usable implementation.)
   *
   * @param signature raw signature, no ASN.1 structure, <code>null</code> or empty not permitted
   * @param signedData data which was signed, <code>null</code> not permitted
   * @param pubKey public key of signer, <code>null</code> not permitted
   * @param mdAlg hash algorithm used in signing, <code>null</code> not permitted, must be a valid hash
   *          algorithm name
   * @return <code>true</code> in case of signature verified successfully, <code>false</code> otherwise
   * @throws IllegalArgumentException if any argument <code>null</code> or signature empty
   * @throws NoSuchAlgorithmException if given digest algorithm unknown
   */
  public static boolean verifySignature(byte[] signature, byte[] signedData, ECPublicKey pubKey, String mdAlg)
    throws NoSuchAlgorithmException
  {
    AssertUtil.notNullOrEmpty(signature, "signature");
    AssertUtil.notNull(signedData, "signed data");
    AssertUtil.notNull(pubKey, "public key");
    AssertUtil.notNull(mdAlg, "digest algorithm");

    BigInteger r = new BigInteger(1, ByteUtil.subbytes(signature, 0, signature.length / 2));
    BigInteger s = new BigInteger(1, ByteUtil.subbytes(signature, signature.length / 2));

    BigInteger n = pubKey.getParams().getOrder();

    if (n.compareTo(r) < 1 || n.compareTo(s) < 1 || r.compareTo(BigInteger.valueOf(0)) < 1
        || s.compareTo(BigInteger.valueOf(0)) < 1)
    {
      return false;
    }

    MessageDigest md = MessageDigest.getInstance(mdAlg);
    byte[] digest = md.digest(signedData);

    BigInteger sInv = s.modInverse(n);

    BigInteger u1 = sInv.multiply(OS2I(digest)).mod(n);
    BigInteger u2 = sInv.multiply(r).mod(n);

    BigInteger a = pubKey.getParams().getCurve().getA();
    BigInteger prime = ((ECFieldFp)pubKey.getParams().getCurve().getField()).getP();

    ECPoint q1 = multiplyECPoint(pubKey.getParams().getGenerator(), u1, a, prime);
    ECPoint q2 = multiplyECPoint(pubKey.getW(), u2, a, prime);
    ECPoint q = addECPoints(q1, q2, a, prime);

    BigInteger v = q.getAffineX();
    if (v.equals(r))
    {
      return true;
    }
    return false;
  }

  /**
   * Conversion from octet string to integer.
   *
   * @param os octet string as byte-array
   * @return {@link BigInteger} representing converted octet string
   * @throws IllegalArgumentException if <code>null</code> given as octet string
   */
  private static final BigInteger OS2I(byte[] os)
  {
    if (os == null)
    {
      throw new IllegalArgumentException("null array not permitted");
    }
    if (os.length == 0)
    {
      return BigInteger.valueOf(0);
    }
    return new BigInteger(1, os);
  }

  /**
   * Checks if a given EC point is on a given EC curve.
   *
   * @param w point
   * @param ecSpec parameters containing curve of Fp type
   * @return <code>true</code> if point on curve, <code>false</code> otherwise
   * @throws IllegalArgumentException if any argument <code>null</code> or given curve not of Fp type
   */
  static boolean isPointOnCurve(ECPoint w, ECParameterSpec ecSpec)
  {
    AssertUtil.notNull(w, "point");
    AssertUtil.notNull(ecSpec, "parameter spec");
    if (!(ecSpec.getCurve().getField() instanceof ECFieldFp))
    {
      throw new IllegalArgumentException("curve not of Fp type");
    }

    BigInteger prime = ((ECFieldFp)ecSpec.getCurve().getField()).getP();

    BigInteger b1 = w.getAffineY().multiply(w.getAffineY()).mod(prime);
    BigInteger b2 = w.getAffineX()
                     .multiply(w.getAffineX())
                     .multiply(w.getAffineX())
                     .add(ecSpec.getCurve().getA().multiply(w.getAffineX()))
                     .add(ecSpec.getCurve().getB())
                     .mod(prime);
    return b1.equals(b2);
  }
}
