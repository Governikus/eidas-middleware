/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.constants;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import lombok.experimental.UtilityClass;


/**
 * OID constants for nPA.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@UtilityClass
public final class OIDConstants
{

  /**
   * OID of id-ecPublicKey: <code>1.2.840.10045.2.1</code>.
   */
  public static final OID OID_EC_PUBLIC_KEY = new OID("1.2.840.10045.2.1");

  /**
   * OID of signature algorithm ECDSA with SHA-256.
   */
  public static final OID OID_ECDSA_SHA256 = new OID("1.2.840.10045.4.3.2");

  /**
   * OID of signature algorithm ECDSA with SHA-384.
   */
  public static final OID OID_ECDSA_SHA384 = new OID("1.2.840.10045.4.3.3");

  /**
   * OID of signature algorithm ECDSA with SHA-512.
   */
  public static final OID OID_ECDSA_SHA512 = new OID("1.2.840.10045.4.3.4");

  /**
   * OID of BSI: <code>0.4.0.127.0.7</code>.
   */
  public static final OID OID_BSI = new OID("0.4.0.127.0.7");

  /**
   * OID of standardized domain parameters: <code>0.4.0.127.0.7.1.2</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_STANDARDIZED_DOMAIN_PARAMETERS = new OID(OID_BSI.getOIDString() + ".1.2");

  /**
   * OID of <b>p</b>ublic <b>k</b>ey: <code>0.4.0.127.0.7.2.2.1</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_PK = new OID(OID_BSI.getOIDString() + ".2.2.1");

  /**
   * OID of Diffie Hellmann <b>p</b>ublic <b>k</b>ey: <code>0.4.0.127.0.7.2.2.1.1</code>.
   *
   * @see #OID_PK
   */
  public static final OID OID_PK_DH = new OID(OID_PK.getOIDString() + ".1");

  /**
   * OID of Elliptic Curve Diffie Hellman <b>p</b>ublic <b>k</b>ey: <code>0.4.0.127.0.7.2.2.1.2</code>.
   *
   * @see #OID_PK
   */
  public static final OID OID_PK_ECDH = new OID(OID_PK.getOIDString() + ".2");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>p</b>ublic <b>k</b>ey: <code>0.4.0.127.0.7.2.2.1.3</code>.
   *
   * @see #OID_PK
   */
  public static final OID OID_PK_PS = new OID(OID_PK.getOIDString() + ".3");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>p</b>ublic <b>k</b>ey: <code>0.4.0.127.0.7.2.2.1.3.2</code>.
   *
   * @see #OID_PK_PS
   */
  public static final OID OID_PK_PS_ECDH_ECSCHNORR = new OID(OID_PK_PS.getOIDString() + ".2");

  /**
   * OID of terminal authentication: <code>0.4.0.127.0.7.2.2.2</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_TA = new OID(OID_BSI.getOIDString() + ".2.2.2");

  /**
   * OID of terminal authentication using RSA: <code>0.4.0.127.0.7.2.2.2.1</code>.
   *
   * @see #OID_TA
   */
  public static final OID OID_TA_RSA = new OID(OID_TA.getOIDString() + ".1");

  /**
   * OID of terminal authentication using RSA with 1.5 padding and SHA1: <code>0.4.0.127.0.7.2.2.2.1.1</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_V1_5_SHA_1 = new OID(OID_TA_RSA.getOIDString() + ".1");

  /**
   * OID of terminal authentication using RSA with 1.5 padding and SHA256: <code>0.4.0.127.0.7.2.2.2.1.2</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_V1_5_SHA_256 = new OID(OID_TA_RSA.getOIDString() + ".2");

  /**
   * OID of terminal authentication using RSA with PSS padding and SHA1: <code>0.4.0.127.0.7.2.2.2.1.3</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_PSS_SHA_1 = new OID(OID_TA_RSA.getOIDString() + ".3");

  /**
   * OID of terminal authentication using RSA with PSS padding and SHA256: <code>0.4.0.127.0.7.2.2.2.1.4</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_PSS_SHA_256 = new OID(OID_TA_RSA.getOIDString() + ".4");

  /**
   * OID of terminal authentication using RSA with 1.5 padding and SHA512: <code>0.4.0.127.0.7.2.2.2.1.5</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_V1_5_SHA_512 = new OID(OID_TA_RSA.getOIDString() + ".5");

  /**
   * OID of terminal authentication using RSA with PSS padding and SHA512: <code>0.4.0.127.0.7.2.2.2.1.6</code>.
   *
   * @see #OID_TA_RSA
   */
  public static final OID OID_TA_RSA_PSS_SHA_512 = new OID(OID_TA_RSA.getOIDString() + ".6");

  /**
   * OID of terminal authentication using ECDSA: <code>0.4.0.127.0.7.2.2.2.2</code>.
   *
   * @see #OID_TA
   */
  public static final OID OID_TA_ECDSA = new OID(OID_TA.getOIDString() + ".2");

  /**
   * OID of terminal authentication using ECDSA with SHA1: <code>0.4.0.127.0.7.2.2.2.2.1</code>.
   *
   * @see #OID_TA_ECDSA
   */
  public static final OID OID_TA_ECDSA_SHA_1 = new OID(OID_TA_ECDSA.getOIDString() + ".1");

  /**
   * OID of terminal authentication using ECDSA with SHA224: <code>0.4.0.127.0.7.2.2.2.2.2</code>.
   *
   * @see #OID_TA_ECDSA
   */
  public static final OID OID_TA_ECDSA_SHA_224 = new OID(OID_TA_ECDSA.getOIDString() + ".2");

  /**
   * OID of terminal authentication using ECDSA with SHA256: <code>0.4.0.127.0.7.2.2.2.2.3</code>.
   *
   * @see #OID_TA_ECDSA
   */
  public static final OID OID_TA_ECDSA_SHA_256 = new OID(OID_TA_ECDSA.getOIDString() + ".3");

  /**
   * OID of terminal authentication using ECDSA with SHA384: <code>0.4.0.127.0.7.2.2.2.2.4</code>.
   *
   * @see #OID_TA_ECDSA
   */
  public static final OID OID_TA_ECDSA_SHA_384 = new OID(OID_TA_ECDSA.getOIDString() + ".4");

  /**
   * OID of terminal authentication using ECDSA with SHA512: <code>0.4.0.127.0.7.2.2.2.2.5</code>.
   *
   * @see #OID_TA_ECDSA
   */
  public static final OID OID_TA_ECDSA_SHA_512 = new OID(OID_TA_ECDSA.getOIDString() + ".5");

  /**
   * OID of chip authentication: <code>0.4.0.127.0.7.2.2.3</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_CA = new OID(OID_BSI.getOIDString() + ".2.2.3");

  /**
   * OID of chip authentication with Diffie Hellman: <code>0.4.0.127.0.7.2.2.3.1</code>.
   *
   * @see #OID_CA
   */
  public static final OID OID_CA_DH = new OID(OID_CA.getOIDString() + ".1");

  /**
   * OID of chip authentication with Diffie Hellman with TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.3.1.1</code>.
   *
   * @see #OID_CA_DH
   */
  public static final OID OID_CA_DH_3DES_CBC_CBC = new OID(OID_CA_DH.getOIDString() + ".1");

  /**
   * OID of chip authentication with Diffie Hellman with AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.3.1.2</code>.
   *
   * @see #OID_CA_DH
   */
  public static final OID OID_CA_DH_AES_CBC_CMAC_128 = new OID(OID_CA_DH.getOIDString() + ".2");

  /**
   * OID of chip authentication with Diffie Hellman with AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.3.1.3</code>.
   *
   * @see #OID_CA_DH
   */
  public static final OID OID_CA_DH_AES_CBC_CMAC_192 = new OID(OID_CA_DH.getOIDString() + ".3");

  /**
   * OID of chip authentication with Diffie Hellman with AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.3.1.4</code>.
   *
   * @see #OID_CA_DH
   */
  public static final OID OID_CA_DH_AES_CBC_CMAC_256 = new OID(OID_CA_DH.getOIDString() + ".4");

  /**
   * OID of chip authentication with Elliptic Curve Diffie Hellman: <code>0.4.0.127.0.7.2.2.3.2</code>.
   *
   * @see #OID_CA
   */
  public static final OID OID_CA_ECDH = new OID(OID_CA.getOIDString() + ".2");

  /**
   * OID of chip authentication with Elliptic Curve Diffie Hellman with TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.3.2.1</code>.
   *
   * @see #OID_CA_ECDH
   */
  public static final OID OID_CA_ECDH_3DES_CBC_CBC = new OID(OID_CA_ECDH.getOIDString() + ".1");

  /**
   * OID of chip authentication with Elliptic Curve Diffie Hellman with AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.3.2.2</code>.
   *
   * @see #OID_CA_ECDH
   */
  public static final OID OID_CA_ECDH_AES_CBC_CMAC_128 = new OID(OID_CA_ECDH.getOIDString() + ".2");

  /**
   * OID of chip authentication with Elliptic Curve Diffie Hellman with AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.3.2.3</code>.
   *
   * @see #OID_CA_ECDH
   */
  public static final OID OID_CA_ECDH_AES_CBC_CMAC_192 = new OID(OID_CA_ECDH.getOIDString() + ".3");

  /**
   * OID of chip authentication with Elliptic Curve Diffie Hellman with AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.3.2.4</code>.
   *
   * @see #OID_CA_ECDH
   */
  public static final OID OID_CA_ECDH_AES_CBC_CMAC_256 = new OID(OID_CA_ECDH.getOIDString() + ".4");

  /**
   * OID of PACE: <code>0.4.0.127.0.7.2.2.4</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_PACE = new OID(OID_BSI.getOIDString() + ".2.2.4");

  /**
   * OID of PACE with Diffie Hellman and General Mapping: <code>0.4.0.127.0.7.2.2.4.1</code>.
   *
   * @see #OID_PACE
   */
  public static final OID OID_PACE_DH_GM = new OID(OID_PACE.getOIDString() + ".1");

  /**
   * OID of PACE with Diffie Hellman, General Mapping, TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.4.1.1</code>.
   *
   * @see #OID_PACE_DH_GM
   */
  public static final OID OID_PACE_DH_GM_3DES_CBC_CBC = new OID(OID_PACE_DH_GM.getOIDString() + ".1");

  /**
   * OID of PACE with Diffie Hellman, General Mapping, AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.4.1.2</code>.
   *
   * @see #OID_PACE_DH_GM
   */
  public static final OID OID_PACE_DH_GM_AES_CBC_CMAC_128 = new OID(OID_PACE_DH_GM.getOIDString() + ".2");

  /**
   * OID of PACE with Diffie Hellman, General Mapping, AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.4.1.3</code>.
   *
   * @see #OID_PACE_DH_GM
   */
  public static final OID OID_PACE_DH_GM_AES_CBC_CMAC_192 = new OID(OID_PACE_DH_GM.getOIDString() + ".3");

  /**
   * OID of PACE with Diffie Hellman, General Mapping, AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.4.1.4</code>.
   *
   * @see #OID_PACE_DH_GM
   */
  public static final OID OID_PACE_DH_GM_AES_CBC_CMAC_256 = new OID(OID_PACE_DH_GM.getOIDString() + ".4");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman and General Mapping: <code>0.4.0.127.0.7.2.2.4.2</code>.
   *
   * @see #OID_PACE
   */
  public static final OID OID_PACE_ECDH_GM = new OID(OID_PACE.getOIDString() + ".2");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, General Mapping, TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.4.2.1</code>.
   *
   * @see #OID_PACE_ECDH_GM
   */
  public static final OID OID_PACE_ECDH_GM_3DES_CBC_CBC = new OID(OID_PACE_ECDH_GM.getOIDString() + ".1");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, General Mapping, AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.4.2.2</code>.
   *
   * @see #OID_PACE_ECDH_GM
   */
  public static final OID OID_PACE_ECDH_GM_AES_CBC_CMAC_128 = new OID(OID_PACE_ECDH_GM.getOIDString() + ".2");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, General Mapping, AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.4.2.3</code>.
   *
   * @see #OID_PACE_ECDH_GM
   */
  public static final OID OID_PACE_ECDH_GM_AES_CBC_CMAC_192 = new OID(OID_PACE_ECDH_GM.getOIDString() + ".3");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, General Mapping, AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.4.2.4</code>.
   *
   * @see #OID_PACE_ECDH_GM
   */
  public static final OID OID_PACE_ECDH_GM_AES_CBC_CMAC_256 = new OID(OID_PACE_ECDH_GM.getOIDString() + ".4");

  /**
   * OID of PACE with Diffie Hellman and Integrated Mapping: <code>0.4.0.127.0.7.2.2.4.3</code>.
   *
   * @see #OID_PACE
   */
  public static final OID OID_PACE_DH_IM = new OID(OID_PACE.getOIDString() + ".3");

  /**
   * OID of PACE with Diffie Hellman, Integrated Mapping, TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.4.3.1</code>.
   *
   * @see #OID_PACE_DH_IM
   */
  public static final OID OID_PACE_DH_IM_3DES_CBC_CBC = new OID(OID_PACE_DH_IM.getOIDString() + ".1");

  /**
   * OID of PACE with Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.4.3.2</code>.
   *
   * @see #OID_PACE_DH_IM
   */
  public static final OID OID_PACE_DH_IM_AES_CBC_CMAC_128 = new OID(OID_PACE_DH_IM.getOIDString() + ".2");

  /**
   * OID of PACE with Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.4.3.3</code>.
   *
   * @see #OID_PACE_DH_IM
   */
  public static final OID OID_PACE_DH_IM_AES_CBC_CMAC_192 = new OID(OID_PACE_DH_IM.getOIDString() + ".3");

  /**
   * OID of PACE with Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.4.3.4</code>.
   *
   * @see #OID_PACE_DH_IM
   */
  public static final OID OID_PACE_DH_IM_AES_CBC_CMAC_256 = new OID(OID_PACE_DH_IM.getOIDString() + ".4");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman and Integrated Mapping: <code>0.4.0.127.0.7.2.2.4.4</code> .
   *
   * @see #OID_PACE
   */
  public static final OID OID_PACE_ECDH_IM = new OID(OID_PACE.getOIDString() + ".4");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, Integrated Mapping, TripleDES, CBC block mode and CBC:
   * <code>0.4.0.127.0.7.2.2.4.4.1</code>.
   *
   * @see #OID_PACE_ECDH_IM
   */
  public static final OID OID_PACE_ECDH_IM_3DES_CBC_CBC = new OID(OID_PACE_ECDH_IM.getOIDString() + ".1");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC128:
   * <code>0.4.0.127.0.7.2.2.4.4.2</code>.
   *
   * @see #OID_PACE_ECDH_IM
   */
  public static final OID OID_PACE_ECDH_IM_AES_CBC_CMAC_128 = new OID(OID_PACE_ECDH_IM.getOIDString() + ".2");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC192:
   * <code>0.4.0.127.0.7.2.2.4.4.3</code>.
   *
   * @see #OID_PACE_ECDH_IM
   */
  public static final OID OID_PACE_ECDH_IM_AES_CBC_CMAC_192 = new OID(OID_PACE_ECDH_IM.getOIDString() + ".3");

  /**
   * OID of PACE with Elliptic Curve Diffie Hellman, Integrated Mapping, AES, CBC block mode and CMAC256:
   * <code>0.4.0.127.0.7.2.2.4.4.4</code>.
   *
   * @see #OID_PACE_ECDH_IM
   */
  public static final OID OID_PACE_ECDH_IM_AES_CBC_CMAC_256 = new OID(OID_PACE_ECDH_IM.getOIDString() + ".4");

  /**
   * OID of Restricted Identification: <code>0.4.0.127.0.7.2.2.5</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_RI = new OID(OID_BSI.getOIDString() + ".2.2.5");

  /**
   * OID of Restricted Identification with Diffie Hellman: <code>0.4.0.127.0.7.2.2.5.1</code>.
   *
   * @see #OID_RI
   */
  public static final OID OID_RI_DH = new OID(OID_RI.getOIDString() + ".1");

  /**
   * OID of Restricted Identification with Diffie Hellman and SHA1: <code>0.4.0.127.0.7.2.2.5.1.1</code>.
   *
   * @see #OID_RI_DH
   */
  public static final OID OID_RI_DH_SHA_1 = new OID(OID_RI_DH.getOIDString() + ".1");

  /**
   * OID of Restricted Identification with Diffie Hellman and SHA224: <code>0.4.0.127.0.7.2.2.5.1.2</code>.
   *
   * @see #OID_RI_DH
   */
  public static final OID OID_RI_DH_SHA_224 = new OID(OID_RI_DH.getOIDString() + ".2");

  /**
   * OID of Restricted Identification with Diffie Hellman and SHA256: <code>0.4.0.127.0.7.2.2.5.1.3</code>.
   *
   * @see #OID_RI_DH
   */
  public static final OID OID_RI_DH_SHA_256 = new OID(OID_RI_DH.getOIDString() + ".3");

  /**
   * OID of Restricted Identification with Diffie Hellman and SHA384: <code>0.4.0.127.0.7.2.2.5.1.4</code>.
   *
   * @see #OID_RI_DH
   */
  public static final OID OID_RI_DH_SHA_384 = new OID(OID_RI_DH.getOIDString() + ".4");

  /**
   * OID of Restricted Identification with Diffie Hellman and SHA512: <code>0.4.0.127.0.7.2.2.5.1.5</code>.
   *
   * @see #OID_RI_DH
   */
  public static final OID OID_RI_DH_SHA_512 = new OID(OID_RI_DH.getOIDString() + ".5");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman: <code>0.4.0.127.0.7.2.2.5.2</code>.
   *
   * @see #OID_RI
   */
  public static final OID OID_RI_ECDH = new OID(OID_RI.getOIDString() + ".2");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman and SHA1: <code>0.4.0.127.0.7.2.2.5.2.1</code>.
   *
   * @see #OID_RI_ECDH
   */
  public static final OID OID_RI_ECDH_SHA_1 = new OID(OID_RI_ECDH.getOIDString() + ".1");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman and SHA224:
   * <code>0.4.0.127.0.7.2.2.5.2.2</code>.
   *
   * @see #OID_RI_ECDH
   */
  public static final OID OID_RI_ECDH_SHA_224 = new OID(OID_RI_ECDH.getOIDString() + ".2");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman and SHA256:
   * <code>0.4.0.127.0.7.2.2.5.2.3</code>.
   *
   * @see #OID_RI_ECDH
   */
  public static final OID OID_RI_ECDH_SHA_256 = new OID(OID_RI_ECDH.getOIDString() + ".3");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman and SHA384:
   * <code>0.4.0.127.0.7.2.2.5.2.4</code>.
   *
   * @see #OID_RI_ECDH
   */
  public static final OID OID_RI_ECDH_SHA_384 = new OID(OID_RI_ECDH.getOIDString() + ".4");

  /**
   * OID of Restricted Identification with Elliptic Curve Diffie Hellman and SHA512:
   * <code>0.4.0.127.0.7.2.2.5.2.5</code>.
   *
   * @see #OID_RI_ECDH
   */
  public static final OID OID_RI_ECDH_SHA_512 = new OID(OID_RI_ECDH.getOIDString() + ".5");

  /**
   * OID of <b>C</b>ard<b>I</b>nfo: <code>0.4.0.127.0.7.2.2.6</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_CI = new OID(OID_BSI.getOIDString() + ".2.2.6");

  /**
   * OID of <b>e</b>ID<b>S</b>ecurity<b>I</b>nfo: <code>0.4.0.127.0.7.2.2.7</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_ESI = new OID(OID_BSI.getOIDString() + ".2.2.7");

  /**
   * OID of <b>P</b>riviliged <b>T</b>erminal <b>I</b>nfo: <code>0.4.0.127.0.7.2.2.8</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_PTI = new OID(OID_BSI.getOIDString() + ".2.2.8");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature: <code>0.4.0.127.0.7.2.2.11</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_PS = new OID(OID_BSI.getOIDString() + ".2.2.11");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>A</b>uthentication: <code>0.4.0.127.0.7.2.2.11.1</code>.
   *
   * @see #OID_PS
   */
  public static final OID OID_PSA = new OID(OID_PS.getOIDString() + ".1");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>A</b>uthentication-ECDH-ECSchnorr:
   * <code>0.4.0.127.0.7.2.2.11.1.2</code>.
   *
   * @see #OID_PSA
   */
  public static final OID OID_PSA_ECDH_ECSCHNORR = new OID(OID_PSA.getOIDString() + ".2");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>A</b>uthentication-ECDH-ECSchnorr-SHA256:
   * <code>0.4.0.127.0.7.2.2.11.1.2.3</code>.
   *
   * @see #OID_PSA_ECDH_ECSCHNORR
   */
  public static final OID OID_PSA_ECDH_ECSCHNORR_SHA256 = new OID(OID_PSA_ECDH_ECSCHNORR.getOIDString() + ".3");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>A</b>uthentication-ECDH-ECSchnorr-SHA384:
   * <code>0.4.0.127.0.7.2.2.11.1.2.4</code>.
   *
   * @see #OID_PSA_ECDH_ECSCHNORR
   */
  public static final OID OID_PSA_ECDH_ECSCHNORR_SHA384 = new OID(OID_PSA_ECDH_ECSCHNORR.getOIDString() + ".4");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>A</b>uthentication-ECDH-ECSchnorr-SHA512:
   * <code>0.4.0.127.0.7.2.2.11.1.2.5</code>.
   *
   * @see #OID_PSA_ECDH_ECSCHNORR
   */
  public static final OID OID_PSA_ECDH_ECSCHNORR_SHA512 = new OID(OID_PSA_ECDH_ECSCHNORR.getOIDString() + ".5");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>M</b>essages: <code>0.4.0.127.0.7.2.2.11.2</code>.
   *
   * @see #OID_PS
   */
  public static final OID OID_PSM = new OID(OID_PS.getOIDString() + ".2");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>M</b>essages-ECDH-ECSchnorr: <code>0.4.0.127.0.7.2.2.11.2.2</code>.
   *
   * @see #OID_PSM
   */
  public static final OID OID_PSM_ECDH_ECSCHNORR = new OID(OID_PSM.getOIDString() + ".2");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>M</b>essages-ECDH-ECSchnorr-SHA256:
   * <code>0.4.0.127.0.7.2.2.11.2.2.3</code>.
   *
   * @see #OID_PSM_ECDH_ECSCHNORR
   */
  public static final OID OID_PSM_ECDH_ECSCHNORR_SHA256 = new OID(OID_PSM_ECDH_ECSCHNORR.getOIDString() + ".3");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>M</b>essages-ECDH-ECSchnorr-SHA384:
   * <code>0.4.0.127.0.7.2.2.11.2.2.4</code>.
   *
   * @see #OID_PSM_ECDH_ECSCHNORR
   */
  public static final OID OID_PSM_ECDH_ECSCHNORR_SHA384 = new OID(OID_PSM_ECDH_ECSCHNORR.getOIDString() + ".4");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>M</b>essages-ECDH-ECSchnorr-SHA512:
   * <code>0.4.0.127.0.7.2.2.11.2.2.5</code>.
   *
   * @see #OID_PSM_ECDH_ECSCHNORR
   */
  public static final OID OID_PSM_ECDH_ECSCHNORR_SHA512 = new OID(OID_PSM_ECDH_ECSCHNORR.getOIDString() + ".5");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>C</b>redentials: <code>0.4.0.127.0.7.2.2.11.3</code>.
   *
   * @see #OID_PS
   */
  public static final OID OID_PSC = new OID(OID_PS.getOIDString() + ".3");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>C</b>redentials-ECDH-ECSchnorr:
   * <code>0.4.0.127.0.7.2.2.11.3.2</code>.
   *
   * @see #OID_PSC
   */
  public static final OID OID_PSC_ECDH_ECSCHNORR = new OID(OID_PSC.getOIDString() + ".2");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>C</b>redentials-ECDH-ECSchnorr-SHA256:
   * <code>0.4.0.127.0.7.2.2.11.3.2.3</code>.
   *
   * @see #OID_PSC_ECDH_ECSCHNORR
   */
  public static final OID OID_PSC_ECDH_ECSCHNORR_SHA256 = new OID(OID_PSC_ECDH_ECSCHNORR.getOIDString() + ".3");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>C</b>redentials-ECDH-ECSchnorr-SHA384:
   * <code>0.4.0.127.0.7.2.2.11.3.2.4</code>.
   *
   * @see #OID_PSC_ECDH_ECSCHNORR
   */
  public static final OID OID_PSC_ECDH_ECSCHNORR_SHA384 = new OID(OID_PSC_ECDH_ECSCHNORR.getOIDString() + ".4");

  /**
   * OID of <b>P</b>seudonymous <b>S</b>ignature <b>C</b>redentials-ECDH-ECSchnorr-SHA512:
   * <code>0.4.0.127.0.7.2.2.11.3.2.5</code>.
   *
   * @see #OID_PSC_ECDH_ECSCHNORR
   */
  public static final OID OID_PSC_ECDH_ECSCHNORR_SHA512 = new OID(OID_PSC_ECDH_ECSCHNORR.getOIDString() + ".5");

  /**
   * OID of Password Type: <code>0.4.0.127.0.7.2.2.12</code>.
   *
   * @see #OID_BSI
   */
  public static final OID OID_PASSWORD_TYPE = new OID(OID_BSI.getOIDString() + ".2.2.12");

  /**
   * OID of Password Type MRZ: <code>0.4.0.127.0.7.2.2.12.1</code>.
   *
   * @see #OID_PASSWORD_TYPE
   */
  public static final OID OID_PASSWORD_TYPE_MRZ = new OID(OID_PASSWORD_TYPE.getOIDString() + ".1");

  /**
   * OID of Password Type CAN: <code>0.4.0.127.0.7.2.2.12.2</code>.
   *
   * @see #OID_PASSWORD_TYPE
   */
  public static final OID OID_PASSWORD_TYPE_CAN = new OID(OID_PASSWORD_TYPE.getOIDString() + ".2");

  /**
   * OID of Password Type PIN: <code>0.4.0.127.0.7.2.2.12.3</code>.
   *
   * @see #OID_PASSWORD_TYPE
   */
  public static final OID OID_PASSWORD_TYPE_PIN = new OID(OID_PASSWORD_TYPE.getOIDString() + ".3");

  /**
   * OID of Password Type PUK: <code>0.4.0.127.0.7.2.2.12.4</code>.
   *
   * @see #OID_PASSWORD_TYPE
   */
  public static final OID OID_PASSWORD_TYPE_PUK = new OID(OID_PASSWORD_TYPE.getOIDString() + ".4");
}
