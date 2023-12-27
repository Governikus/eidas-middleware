/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.ec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKeyPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.AlgorithmIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.DomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * Utilities for EC parameter specifications.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ECUtil
{

  /**
   * Builds {@link ECParameterSpec} object using the different variants of domain parameter information structures
   * contained in EF.CardAccess.
   *
   * @param paramInfo domain parameter object, <code>null</code> not permitted
   * @return {@link ECParameterSpec} object containing given domain parameters
   * @throws IllegalArgumentException if paramInfo <code>null</code> or unknown type
   * @throws IOException
   */
  public static ECParameterSpec parameterSpecFromDomainParameters(DomainParameterInfo paramInfo) throws IOException
  {
    AssertUtil.notNull(paramInfo, "domain parameter info");

    AlgorithmIdentifier ai = paramInfo.getDomainParameter();
    if (OIDConstants.OID_STANDARDIZED_DOMAIN_PARAMETERS.equals(ai.getAlgorithm()))
    {
      return parameterSpecFromCurveID(ai.getParameterID());
    }
    return parameterSpecFromAlgorithmIdentifier(ai);
  }

  /**
   * Builds {@link ECParameterSpec} from {@link AlgorithmIdentifier} structure.
   *
   * @param ai {@link AlgorithmIdentifier} containing domain parameters, <code>null</code> not permitted
   * @return generated {@link ECParameterSpec}
   * @throws IllegalArgumentException if algorithm identifier <code>null</code>
   * @throws IOException
   */
  private static ECParameterSpec parameterSpecFromAlgorithmIdentifier(AlgorithmIdentifier ai) throws IOException
  {
    AssertUtil.notNull(ai, "algorithm identifier");
    if (!OIDConstants.OID_EC_PUBLIC_KEY.equals(ai.getAlgorithm()))
    {
      throw new IllegalArgumentException("algorithm identifier does not contain explicit EC domain parameters");
    }

    ASN1 params = ai.getParameters();
    BigInteger primeModulus = new BigInteger(ByteUtil.addLeadingZero(params.getChildElementsByTag(0x30)[0].getChildElementsByTag(0x02)[0].getValue()));
    BigInteger firstCoefficient = new BigInteger(ByteUtil.addLeadingZero(params.getChildElementsByTag(0x30)[1].getChildElementsByTag(0x04)[0].getValue()));
    BigInteger secondCoefficient = new BigInteger(ByteUtil.addLeadingZero(params.getChildElementsByTag(0x30)[1].getChildElementsByTag(0x04)[1].getValue()));
    byte[] pointBytes = params.getChildElementsByTag(0x04)[0].getValue();
    BigInteger orderOfBasePoint = new BigInteger(ByteUtil.addLeadingZero(params.getChildElementsByTag(0x02)[1].getValue()));
    BigInteger cofactor = new BigInteger(ByteUtil.addLeadingZero(params.getChildElementsByTag(0x02)[2].getValue()));

    return buildParameterSpec(primeModulus,
                              firstCoefficient,
                              secondCoefficient,
                              pointBytes,
                              orderOfBasePoint,
                              cofactor);
  }

  /**
   * Builds {@link ECParameterSpec} from {@link ECCVCertificate}.
   *
   * @return generated {@link ECParameterSpec}
   * @throws IllegalArgumentException if cert <code>null</code> or not containing domain parameters
   * @throws IOException
   */
  public static ECParameterSpec parameterSpecFromCVC(ECCVCertificate cert) throws IOException
  {
    AssertUtil.notNull(cert, "CVC");
    AssertUtil.notNull(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_COEFFICIENT_A),
                       "domain parameters in CVC");

    BigInteger primeModulus = new BigInteger(ByteUtil.addLeadingZero(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_PRIME_MODULUS)
                                                                         .getValue()));
    BigInteger firstCoefficient = new BigInteger(ByteUtil.addLeadingZero(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_COEFFICIENT_A)
                                                                             .getValue()));
    BigInteger secondCoefficient = new BigInteger(ByteUtil.addLeadingZero(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_COEFFICIENT_B)
                                                                              .getValue()));
    byte[] pointBytes = cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_BASE_POINT_G).getValue();
    BigInteger orderOfBasePoint = new BigInteger(ByteUtil.addLeadingZero(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_ORDER_OF_BASE_POINT_R)
                                                                             .getValue()));
    BigInteger cofactor = new BigInteger(ByteUtil.addLeadingZero(cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_CO_FACTOR_F)
                                                                     .getValue()));

    return buildParameterSpec(primeModulus,
                              firstCoefficient,
                              secondCoefficient,
                              pointBytes,
                              orderOfBasePoint,
                              cofactor);
  }

  /**
   * Builds {@link ECParameterSpec} from {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey}.
   *
   * @param key {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey} to use for creation,
   *          <code>null</code> not permitted, must be a key which contains domain parameters (not every
   *          specimen does)
   * @return generated {@link ECParameterSpec}
   * @throws IllegalArgumentException if key <code>null</code> or not containing domain parameters
   * @throws IOException
   */
  private static ECParameterSpec parameterSpecFromKey(de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey key)
    throws IOException
  {
    AssertUtil.notNull(key, "key");
    AssertUtil.notNull(key.getChildElementByPath(ECPublicKeyPath.COEFFICIENT_A), "domain parameters in key");

    BigInteger primeModulus = new BigInteger(ByteUtil.addLeadingZero(key.getChildElementByPath(ECPublicKeyPath.PRIME_MODULUS)
                                                                        .getValue()));
    BigInteger firstCoefficient = new BigInteger(ByteUtil.addLeadingZero(key.getChildElementByPath(ECPublicKeyPath.COEFFICIENT_A)
                                                                            .getValue()));
    BigInteger secondCoefficient = new BigInteger(ByteUtil.addLeadingZero(key.getChildElementByPath(ECPublicKeyPath.COEFFICIENT_B)
                                                                             .getValue()));
    byte[] pointBytes = key.getChildElementByPath(ECPublicKeyPath.BASE_POINT_G).getValue();
    BigInteger orderOfBasePoint = new BigInteger(ByteUtil.addLeadingZero(key.getChildElementByPath(ECPublicKeyPath.ORDER_OF_BASE_POINT_R)
                                                                            .getValue()));
    BigInteger cofactor = new BigInteger(ByteUtil.addLeadingZero(key.getChildElementByPath(ECPublicKeyPath.CO_FACTOR_F)
                                                                    .getValue()));

    return buildParameterSpec(primeModulus,
                              firstCoefficient,
                              secondCoefficient,
                              pointBytes,
                              orderOfBasePoint,
                              cofactor);
  }

  private static ECParameterSpec buildParameterSpec(BigInteger primeModulus,
                                                    BigInteger firstCoefficient,
                                                    BigInteger secondCoefficient,
                                                    byte[] pointBytes,
                                                    BigInteger orderOfBasePoint,
                                                    BigInteger cofactor)
  {
    AssertUtil.notNull(primeModulus, "prime modulus");
    AssertUtil.notNull(firstCoefficient, "first coefficient");
    AssertUtil.notNull(secondCoefficient, "second coefficient");
    AssertUtil.notNullOrEmpty(pointBytes, "bytes of point");
    AssertUtil.notNull(orderOfBasePoint, "order of base point");
    AssertUtil.notNull(cofactor, "cofactor");

    ECField field = new ECFieldFp(primeModulus);
    EllipticCurve curve = new EllipticCurve(field, firstCoefficient, secondCoefficient);

    ECPoint point = ECMath.pointFromBytes(pointBytes, primeModulus.bitLength() / 8);

    return new ECParameterSpec(curve, point, orderOfBasePoint, cofactor.intValue());
  }

  /**
   * Builds {@link ECParameterSpec} from curve ID (currently usable IDs specified in TR-03110).
   *
   * @param id ID of curve
   * @return generated {@link ECParameterSpec}
   * @throws IllegalArgumentException if invalid ID given
   */
  private static ECParameterSpec parameterSpecFromCurveID(int id)
  {
    if (id < DomainParameterInfo.MIN_DOMAIN_PARAMETER_ID || id > DomainParameterInfo.MAX_DOMAIN_PARAMETER_ID)
    {
      throw new IllegalArgumentException("given curve ID currently not specified");
    }
    return SecurityInfos.getDomainParameterMap().get(id);
  }

  /**
   * Create an {@link ECPublicKey} from an {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey}
   * structure as defined in "Advanced Security Mechanisms for Machine Readable Travel Documents", p. 82. This
   * is the variant to be used if the curve parameters are contained in the
   * {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey} structure.
   *
   * @param keyASN1 {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey} structure containing
   *          data of the public key to be created.
   * @return the created {@link ECPublicKey}, <code>null</code> if creating fails
   * @throws IllegalArgumentException if <code>null</code> given as argument
   */
  public static ECPublicKey createKeyFromASN1(de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey keyASN1)
    throws IOException
  {
    AssertUtil.notNull(keyASN1, "key data");
    ECParameterSpec paramSpec = parameterSpecFromKey(keyASN1);
    return createKeyFromASN1(keyASN1, paramSpec);
  }

  /**
   * Create an {@link ECPublicKey} from an {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey}
   * structure as defined in "Advanced Security Mechanisms for Machine Readable Travel Documents", p. 82. This
   * is the variant to be used if the curve parameters are not contained in the
   * {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey} structure.
   *
   * @param keyASN1 {@link de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey} structure containing
   *          data of the public key to be created.
   * @param paramSpec curve parameters given separately
   * @return the created {@link ECPublicKey}, <code>null</code> if creating fails
   * @throws IllegalArgumentException if <code>null</code> given as argument
   */
  private static ECPublicKey createKeyFromASN1(de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey keyASN1,
                                               ECParameterSpec paramSpec)
    throws IOException
  {
    AssertUtil.notNull(keyASN1, "key data");
    AssertUtil.notNull(paramSpec, "curve parameters");
    byte[] publicPointBytes = keyASN1.getChildElementByPath(ECPublicKeyPath.PUBLIC_POINT_Y).getValue();

    ECPoint point = ECMath.pointFromBytes(publicPointBytes,
                                          paramSpec.getCurve().getField().getFieldSize() / 8);
    return new ECPublicKeyImpl(point, paramSpec);
  }
}
