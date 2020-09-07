/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Integer;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.AlgorithmIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.EIDSecurityObject;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.EIDVersionInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ProtocolParams;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SubjectPublicKeyInfo;


/**
 * Path for child elements of {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class SecurityInfosPath extends ASN1Path
{

  /**
   * Constructor.
   *
   * @param name name
   * @param tagByteString tag of child element as Hex-String
   * @param index index of child element
   * @param parent optional parent path element
   * @param encoderClass Class of {@link ASN1Encoder} for creating ASN1. object with support convenience
   *          methods to access contents of ASN.1, <code>null</code> permitted, any real Class must possess an
   *          empty, accessible Constructor to create an instance, otherwise an
   *          {@link IllegalArgumentException} is thrown
   * @throws IllegalArgumentException if Class of {@link ASN1Encoder} does not possess an empty constructor
   *           for initialization
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path, Class)
   */
  private SecurityInfosPath(String name,
                           String tagByteString,
                           int index,
                           ASN1Path parent,
                           Class<? extends ASN1Encoder> encoderClass)
  {
    super(name, tagByteString, index, parent, encoderClass);
  }

  /**
   * Constructor.
   *
   * @param name name
   * @param tagByteString tag of child element as Hex-String
   * @param index index of child element
   * @param parent optional parent path element
   * @see ASN1Path#ASN1Path(String, String, int, ASN1Path)
   */
  private SecurityInfosPath(String name, String tagByteString, int index, ASN1Path parent)
  {
    super(name, tagByteString, index, parent);
  }

  /**
   * Path to root of any <code>SecurityInfo</code> block. Note: there are typically several security info
   * blocks in the file, therefore it is not possible to connect this path to the root path and it should not
   * be called directly.
   */
  final static SecurityInfosPath SECURITY_INFO = new SecurityInfosPath("SECURITY_INFO", "30", 0, null);

  /**
   * Path to <code>protocol</code> of <code>SecurityInfo</code>.
   */
  public static final SecurityInfosPath SECURITY_INFO_PROTOCOL = new SecurityInfosPath(
                                                                                       "SECURITY_INFO_PROTOCOL",
                                                                                       "06", 0,
                                                                                       SECURITY_INFO,
                                                                                       OID.class);

  /**
   * Path to root of <code>TerminalAuthenticationInfo</code> block. Note: there are typically several security
   * info blocks in the file (in undetermined order), therefore it is not possible to connect this path to the
   * root path and it should not be called directly.
   */
  private static final SecurityInfosPath TERMINAL_AUTHENTICATION_INFO = new SecurityInfosPath(
                                                                                              "TERMINAL_AUTHENTICATION_INFO",
                                                                                              "30", 0, null);

  /**
   * Path to <code>version</code> of <code>TerminalAuthenticationInfo</code> block.
   */
  public static final SecurityInfosPath TERMINAL_AUTHENTICATION_INFO_VERSION = new SecurityInfosPath(
                                                                                                     "TERMINAL_AUTHENTICATION_INFO_VERSION",
                                                                                                     "02",
                                                                                                     0,
                                                                                                     TERMINAL_AUTHENTICATION_INFO,
                                                                                                     ASN1Integer.class);

  /**
   * Path to <code>EFCVCA</code> of <code>TerminalAuthenticationInfo</code> block.
   */
  public static final SecurityInfosPath TERMINAL_AUTHENTICATION_INFO_EFCVCA = new SecurityInfosPath(
                                                                                                    "TERMINAL_AUTHENTICATION_INFO_EFCVCA",
                                                                                                    "02",
                                                                                                    1,
                                                                                                    TERMINAL_AUTHENTICATION_INFO,
                                                                                                    ASN1Integer.class);

  /**
   * Path to root of <code>ChipAuthenticationInfo</code> block. Note: there are typically several security
   * info blocks in the file (in undetermined order), therefore it is not possible to connect this path to the
   * root path and it should not be called directly.
   */
  private static final SecurityInfosPath CHIP_AUTHENTICATION_INFO = new SecurityInfosPath(
                                                                                          "CHIP_AUTHENTICATION_INFO",
                                                                                          "30", 0, null);

  /**
   * Path to <code>version</code> of <code>ChipAuthenticationInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_INFO_VERSION = new SecurityInfosPath(
                                                                                                 "CHIP_AUTHENTICATION_INFO_VERSION",
                                                                                                 "02",
                                                                                                 0,
                                                                                                 CHIP_AUTHENTICATION_INFO,
                                                                                                 ASN1Integer.class);

  /**
   * Path to <code>keyID</code> of <code>ChipAuthenticationInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_INFO_KEY_ID = new SecurityInfosPath(
                                                                                                "CHIP_AUTHENTICATION_KEY_ID",
                                                                                                "02",
                                                                                                1,
                                                                                                CHIP_AUTHENTICATION_INFO,
                                                                                                ASN1Integer.class);

  /**
   * Path to <code>PACEInfo</code> block. Note: there are typically several security info blocks in the file
   * (in undetermined order), therefore it is not possible to connect this path to the root path and it should
   * not be called directly.
   */
  private static final SecurityInfosPath PACE_INFO = new SecurityInfosPath("PACE_INFO", "30", 0, null);

  /**
   * Path to <code>version</code> of <code>PACEInfo</code> block.
   */
  public static final SecurityInfosPath PACE_INFO_VERSION = new SecurityInfosPath("PACE_INFO_VERSION", "02",
                                                                                  0, PACE_INFO,
                                                                                  ASN1Integer.class);

  /**
   * Path to <code>parameterID</code> of <code>PACEInfo</code> block.
   */
  public static final SecurityInfosPath PACE_INFO_PARAMETER_ID = new SecurityInfosPath(
                                                                                       "PACE_INFO_PARAMETER_ID",
                                                                                       "02", 1, PACE_INFO,
                                                                                       ASN1Integer.class);

  /**
   * Path to <code>PrivilegedTerminalInfo</code> block. Note: there are typically several security info blocks
   * in the file (in undetermined order), therefore it is not possible to connect this path to the root path
   * and it should not be called directly.
   */
  private static final SecurityInfosPath PRIVILEGED_TERMINAL_INFO = new SecurityInfosPath(
                                                                                          "PRIVILEGED_TERMINAL_INFO",
                                                                                          "30", 0, null);

  /**
   * Path to <code>privilegedTerminalInfos</code> of <code>PrivilegedTerminalInfo</code> block.
   */
  public static final SecurityInfosPath PRIVILEGED_TERMINAL_INFO_PT_INFOS = new SecurityInfosPath(
                                                                                                  "PRIVILEGED_TERMINAL_INFO_PT_INFOS",
                                                                                                  "31",
                                                                                                  0,
                                                                                                  PRIVILEGED_TERMINAL_INFO,
                                                                                                  SecurityInfos.class);

  /**
   * Path to <code>CardInfo</code> block. Note: there are typically several security info blocks in the file
   * (in undetermined order), therefore it is not possible to connect this path to the root path and it should
   * not be called directly.
   */
  private static final SecurityInfosPath CARD_INFO = new SecurityInfosPath("CARD_INFO", "30", 0, null);

  /**
   * Path to <code>urlCardInfo</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_URL = new SecurityInfosPath("CARD_INFO_LOCATOR_URL", "16",
                                                                              0, CARD_INFO);

  /**
   * Path to <code>EfCardInfo</code> or <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_SEQ = new SecurityInfosPath("CARD_INFO_INNER_SEQ",
                                                                                    "30", 0, CARD_INFO);

  /**
   * Path to <code>fid</code> of <code>EfCardInfo</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_FILEID_FID = new SecurityInfosPath(
                                                                                           "CARD_INFO_INNER_FILEID_FID",
                                                                                           "04", 0,
                                                                                           CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>sfid</code> of <code>EfCardInfo</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_FILEID_SFID = new SecurityInfosPath(
                                                                                            "CARD_INFO_INNER_FILEID_FID",
                                                                                            "04", 1,
                                                                                            CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>efCardInfo</code> of <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  private static final SecurityInfosPath CARD_INFO_INNER_EXTCID_CARDINFO = new SecurityInfosPath(
                                                                                                "CARD_INFO_INNER_EXTCID_CARDINFO",
                                                                                                "80", 0,
                                                                                                CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>fid</code> of <code>EfCardInfo</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_FID = new SecurityInfosPath(
                                                                                           "CARD_INFO_INNER_EXTCID_FID",
                                                                                           "04", 0,
                                                                                           CARD_INFO_INNER_EXTCID_CARDINFO);

  /**
   * Path to <code>sfid</code> of <code>EfCardInfo</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_SFID = new SecurityInfosPath(
                                                                                            "CARD_INFO_INNER_EXTCID_SFID",
                                                                                            "04", 1,
                                                                                            CARD_INFO_INNER_EXTCID_CARDINFO);

  /**
   * Path to <code>supportedTRVersion</code> of <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_TRVERSION = new SecurityInfosPath(
                                                                                                 "CARD_INFO_INNER_EXTCID_TRVERSION",
                                                                                                 "81", 0,
                                                                                                 CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>suppTerminalTypes</code> of <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_TERMTYPES = new SecurityInfosPath(
                                                                                                 "CARD_INFO_INNER_EXTCID_TERMTYPES",
                                                                                                 "82", 0,
                                                                                                 CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>maxSCNo</code> of <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_MAXSC = new SecurityInfosPath(
                                                                                             "CARD_INFO_INNER_EXTCID_MAXSC",
                                                                                             "83",
                                                                                             0,
                                                                                             CARD_INFO_INNER_SEQ,
                                                                                             ASN1Integer.class);

  /**
   * Path to <code>envInfo</code> of <code>ExtCardInfoData</code> of <code>CardInfo</code> block.
   */
  public static final SecurityInfosPath CARD_INFO_INNER_EXTCID_ENVINFO = new SecurityInfosPath(
                                                                                               "CARD_INFO_INNER_EXTCID_ENVINFO",
                                                                                               "84", 0,
                                                                                               CARD_INFO_INNER_SEQ);

  /**
   * Path to <code>SupportedTerminalTypes</code> block. Note: there are typically several security info blocks
   * in the file (in undetermined order), therefore it is not possible to connect this path to the root path
   * and it should not be called directly.
   */
  private static final SecurityInfosPath SUPPORTED_TERMINAL_TYPES = new SecurityInfosPath(
                                                                                          "SUPPORTED_TERMINAL_TYPES",
                                                                                          "30", 0, null);

  /**
   * Path to <code>supportedTerminalType</code> of <code>SupportedTerminalTypes</code>.
   */
  public static final SecurityInfosPath SUPPORTED_TERMINAL_TYPES_TERMINAL_TYPE = new SecurityInfosPath(
                                                                                                       "SUPPORTED_TERMINAL_TYPES_TERMINAL_TYPE",
                                                                                                       "06",
                                                                                                       0,
                                                                                                       SUPPORTED_TERMINAL_TYPES,
                                                                                                       OID.class);

  /**
   * Path to <code>supportedAuthorizations</code> of <code>SupportedTerminalTypes</code>.
   */
  public static final SecurityInfosPath SUPPORTED_TERMINAL_TYPES_AUTHORIZATIONS = new SecurityInfosPath(
                                                                                                        "SUPPORTED_TERMINAL_TYPES_AUTHORIZATIONS",
                                                                                                        "31",
                                                                                                        0,
                                                                                                        SUPPORTED_TERMINAL_TYPES);

  /**
   * Path to <code>ChipAuthenticationDomainParameterInfo</code> block. Note: there are typically several
   * security info blocks in the file (in undetermined order), therefore it is not possible to connect this
   * path to the root path and it should not be called directly.
   */
  private static final SecurityInfosPath CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO = new SecurityInfosPath(
                                                                                                           "CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO",
                                                                                                           "30",
                                                                                                           0,
                                                                                                           null);

  /**
   * Path to <code>domainParameter</code> of <code>ChipAuthenticationDomainParameterInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER = new SecurityInfosPath(
                                                                                                                           "CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER",
                                                                                                                           "30",
                                                                                                                           0,
                                                                                                                           CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO,
                                                                                                                           AlgorithmIdentifier.class);

  /**
   * Path to <code>keyID</code> of <code>ChipAuthenticationDomainParameterInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO_KEY_ID = new SecurityInfosPath(
                                                                                                                 "CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO_KEY_ID",
                                                                                                                 "02",
                                                                                                                 0,
                                                                                                                 CHIP_AUTHENTICATION_DOMAIN_PARAMETER_INFO,
                                                                                                                 ASN1Integer.class);

  /**
   * Path to <code>PACEDomainParameterInfo</code> block. Note: there are typically several security info
   * blocks in the file (in undetermined order), therefore it is not possible to connect this path to the root
   * path and it should not be called directly.
   */
  private static final SecurityInfosPath PACE_DOMAIN_PARAMETER_INFO = new SecurityInfosPath(
                                                                                            "PACE_DOMAIN_PARAMETER_INFO",
                                                                                            "30", 0, null);

  /**
   * Path to <code>domainParameter</code> of <code>PACEDomainParameterInfo</code> block.
   */
  public static final SecurityInfosPath PACE_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER = new SecurityInfosPath(
                                                                                                            "PACE_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER",
                                                                                                            "30",
                                                                                                            0,
                                                                                                            PACE_DOMAIN_PARAMETER_INFO,
                                                                                                            AlgorithmIdentifier.class);

  /**
   * Path to <code>parameterID</code> of <code>PACEDomainParameterInfo</code> block.
   */
  public static final SecurityInfosPath PACE_DOMAIN_PARAMETER_INFO_PARAMETER_ID = new SecurityInfosPath(
                                                                                                        "PACE_DOMAIN_PARAMETER_INFO_PARAMETER_ID",
                                                                                                        "02",
                                                                                                        0,
                                                                                                        PACE_DOMAIN_PARAMETER_INFO,
                                                                                                        ASN1Integer.class);

  /**
   * Path to <code>ChipAuthenticationPublicKeyInfo</code> block. Note: there are typically several security
   * info blocks in the file (in undetermined order), therefore it is not possible to connect this path to the
   * root path and it should not be called directly.
   */
  private static final SecurityInfosPath CHIP_AUTHENTICATION_PUBLIC_KEY_INFO = new SecurityInfosPath(
                                                                                                     "CHIP_AUTHENTICATION_PUBLIC_KEY_INFO",
                                                                                                     "30", 0,
                                                                                                     null);

  /**
   * Path to <code>chipAuthenticationPublicKey</code> of <code>ChipAuthenticationPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_CHIP_AUTHENTICATION_PUBLIC_KEY = new SecurityInfosPath(
                                                                                                                                   "CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_PUBLIC KEY",
                                                                                                                                   "30",
                                                                                                                                   0,
                                                                                                                                   CHIP_AUTHENTICATION_PUBLIC_KEY_INFO,
                                                                                                                                   SubjectPublicKeyInfo.class);

  /**
   * Path to <code>chipAuthenticationKeyID</code> of <code>ChipAuthenticationPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_KEY_ID = new SecurityInfosPath(
                                                                                                           "CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_KEY_ID",
                                                                                                           "02",
                                                                                                           0,
                                                                                                           CHIP_AUTHENTICATION_PUBLIC_KEY_INFO,
                                                                                                           ASN1Integer.class);


  /**
   * Path to <code>SubjectPublicKeyInfo</code> block. Note: there can be several of these blocks in the file
   * (at different places), therefore it is not possible to connect this path to the root path and it should
   * not be called directly.
   */
  private static final SecurityInfosPath SUBJECT_PUBLIC_KEY_INFO = new SecurityInfosPath(
                                                                                         "SUBJECT_PUBLIC_KEY_INFO",
                                                                                         "30", 0, null);

  /**
   * Path to <code>algorithm</code> of <code>SubjectPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath SUBJECT_PUBLIC_KEY_INFO_ALGORITHM = new SecurityInfosPath(
                                                                                                  "SUBJECT_PUBLIC_KEY_INFO_ALGORITHM",
                                                                                                  "30",
                                                                                                  0,
                                                                                                  SUBJECT_PUBLIC_KEY_INFO,
                                                                                                  AlgorithmIdentifier.class);

  /**
   * Path to <code>subjectPublicKey</code> of <code>SubjectPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath SUBJECT_PUBLIC_KEY_INFO_SUBJECT_PUBLIC_KEY = new SecurityInfosPath(
                                                                                                           "SUBJECT_PUBLIC_KEY_INFO_SUBJECT_PUBLIC KEY",
                                                                                                           "03",
                                                                                                           0,
                                                                                                           SUBJECT_PUBLIC_KEY_INFO);

  /**
   * Path to <code>AlgorithmIdentifier</code> block. Note: there can be several of these blocks in the file
   * (at different places), therefore it is not possible to connect this path to the root path and it should
   * not be called directly.
   */
  private static final SecurityInfosPath ALGORITHM_IDENTIFIER = new SecurityInfosPath("ALGORITHM_IDENTIFIER",
                                                                                      "30", 0, null);

  /**
   * Path to <code>algorithm</code> of <code>AlgorithmIdentifier</code> block.
   */
  public static final SecurityInfosPath ALGORITHM_IDENTIFIER_ALGORITHM = new SecurityInfosPath(
                                                                                               "ALGORITHM_IDENTIFIER_ALGORITHM",
                                                                                               "06",
                                                                                               0,
                                                                                               ALGORITHM_IDENTIFIER,
                                                                                               OID.class);

  /**
   * Path to <code>parameters</code> of <code>AlgorithmIdentifier</code> block (case: full parameters).
   */
  public static final SecurityInfosPath ALGORITHM_IDENTIFIER_PARAMETERS = new SecurityInfosPath(
                                                                                                "ALGORITHM_IDENTIFIER_PARAMETERS",
                                                                                                "30", 0,
                                                                                                ALGORITHM_IDENTIFIER);

  /**
   * Path to <code>parameters</code> of <code>AlgorithmIdentifier</code> block (case: ID).
   */
  public static final SecurityInfosPath ALGORITHM_IDENTIFIER_PARAMETER_ID = new SecurityInfosPath(
                                                                                                  "ALGORITHM_IDENTIFIER_PARAMETER_ID",
                                                                                                  "02",
                                                                                                  0,
                                                                                                  ALGORITHM_IDENTIFIER,
                                                                                                  ASN1Integer.class);

  /**
   * Path to <code>RestrictedIdentificationInfo</code> block. Note: there are typically several security info
   * blocks in the file (in undetermined order), therefore it is not possible to connect this path to the root
   * path and it should not be called directly.
   */
  private static final SecurityInfosPath RESTRICTED_IDENTIFICATION_INFO = new SecurityInfosPath(
                                                                                                "RESTRICTED_IDENTIFICATION_INFO",
                                                                                                "30", 0, null);

  /**
   * Path to <code>params</code> of <code>RestrictedIdentificationInfo</code> block.
   */
  public static final SecurityInfosPath RESTRICTED_IDENTIFICATION_INFO_PARAMS = new SecurityInfosPath(
                                                                                                      "RESTRICTED_IDENTIFICATION_INFO_PARAMS",
                                                                                                      "30",
                                                                                                      0,
                                                                                                      RESTRICTED_IDENTIFICATION_INFO,
                                                                                                      ProtocolParams.class);

  /**
   * Path to <code>maxKeyLen</code> of <code>RestrictedIdentificationInfo</code> block.
   */
  public static final SecurityInfosPath RESTRICTED_IDENTIFICATION_INFO_MAXKEYLEN = new SecurityInfosPath(
                                                                                                         "RESTRICTED_IDENTIFICATION_INFO_MAXKEYLEN",
                                                                                                         "02",
                                                                                                         0,
                                                                                                         RESTRICTED_IDENTIFICATION_INFO,
                                                                                                         ASN1Integer.class);

  /**
   * Path to <code>RestrictedIdentificationDomainParameterInfo</code> block. Note: there are typically several
   * security info blocks in the file (in undetermined order), therefore it is not possible to connect this
   * path to the root path and it should not be called directly.
   */
  private static final SecurityInfosPath RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO = new SecurityInfosPath(
                                                                                                                 "RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO",
                                                                                                                 "30",
                                                                                                                 0,
                                                                                                                 null);

  /**
   * Path to <code>domainParameter</code> of <code>RestrictedIdentificationDomainParameterInfo</code> block.
   */
  public static final SecurityInfosPath RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER = new SecurityInfosPath(
                                                                                                                                 "RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER",
                                                                                                                                 "30",
                                                                                                                                 0,
                                                                                                                                 RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO,
                                                                                                                                 AlgorithmIdentifier.class);

  /**
   * Path to <code>ProtocolParams</code> block. Note: there can be several of these blocks in the file (at
   * different places), therefore it is not possible to connect this path to the root path and it should not
   * be called directly.
   */
  private static final SecurityInfosPath PROTOCOL_PARAMS = new SecurityInfosPath("PROTOCOL_PARAMS", "30", 0,
                                                                                 null);

  /**
   * Path to <code>version</code> of <code>ProtocolParams</code> block.
   */
  public static final SecurityInfosPath PROTOCOL_PARAMS_VERSION = new SecurityInfosPath(
                                                                                        "PROTOCOL_PARAMS_VERSION",
                                                                                        "02", 0,
                                                                                        PROTOCOL_PARAMS,
                                                                                        ASN1Integer.class);

  /**
   * Path to <code>keyID</code> of <code>ProtocolParams</code> block.
   */
  public static final SecurityInfosPath PROTOCOL_PARAMS_KEYID = new SecurityInfosPath(
                                                                                      "PROTOCOL_PARAMS_KEYID",
                                                                                      "02", 1,
                                                                                      PROTOCOL_PARAMS,
                                                                                      ASN1Integer.class);

  /**
   * Path to <code>authorizedOnly</code> of <code>ProtocolParams</code> block.
   */
  public static final SecurityInfosPath PROTOCOL_PARAMS_AUTHORIZEDONLY = new SecurityInfosPath(
                                                                                               "PROTOCOL_PARAMS_AUTHORIZEDONLY",
                                                                                               "01", 0,
                                                                                               PROTOCOL_PARAMS);

  /**
   * Path to <code>eIDSecurityInfo</code> block. Note: there are typically several security info blocks in the
   * file (in undetermined order), therefore it is not possible to connect this path to the root path and it
   * should not be called directly.
   */
  private static final SecurityInfosPath EID_SECURITY_INFO = new SecurityInfosPath("EID_SECURITY_INFO", "30",
                                                                                   0, null);

  /**
   * Path to <code>eIDSecurityObject</code> of <code>eIDSecurityInfo</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_OBJECT = new SecurityInfosPath(
                                                                                         "EID_SECURITY_INFO_OBJECT",
                                                                                         "30",
                                                                                         0,
                                                                                         EID_SECURITY_INFO,
                                                                                         EIDSecurityObject.class);

  /**
   * Path to <code>hashAlgorithm</code> of <code>EIDSecurityObject</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_OBJECT_HASH_ALG = new SecurityInfosPath(
                                                                                                  "EID_SECURITY_INFO_OBJECT_HASH_ALG",
                                                                                                  "30",
                                                                                                  0,
                                                                                                  EID_SECURITY_INFO_OBJECT,
                                                                                                  AlgorithmIdentifier.class);

  /**
   * Path to <code>dataGroupHashValues</code> of <code>EIDSecurityObject</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_OBJECT_HASH_VALUES = new SecurityInfosPath(
                                                                                                     "EID_SECURITY_INFO_OBJECT_HASH_VALUES",
                                                                                                     "30", 1,
                                                                                                     EID_SECURITY_INFO_OBJECT);

  /**
   * Path to <code>eIDVersionInfo</code> of <code>eIDSecurityInfo</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_VERSION = new SecurityInfosPath(
                                                                                          "EID_SECURITY_INFO_VERSION",
                                                                                          "30",
                                                                                          1,
                                                                                          EID_SECURITY_INFO,
                                                                                          EIDVersionInfo.class);

  /**
   * Path to <code>eIDVersion</code> of <code>EIDVersionInfo</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_VERSION_EID = new SecurityInfosPath(
                                                                                              "EID_SECURITY_INFO_VERSION_EID",
                                                                                              "13", 0,
                                                                                              EID_SECURITY_INFO_VERSION);

  /**
   * Path to <code>unicodeVersion</code> of <code>EIDVersionInfo</code> block.
   */
  public static final SecurityInfosPath EID_SECURITY_INFO_VERSION_UNICODE = new SecurityInfosPath(
                                                                                                  "EID_SECURITY_INFO_VERSION_UNICODE",
                                                                                                  "13", 1,
                                                                                                  EID_SECURITY_INFO_VERSION);

  /**
   * Path to <code>DataGroupHash</code> block. Note: there can be several of these blocks in the file (at
   * different places), therefore it is not possible to connect this path to the root path and it should not
   * be called directly.
   */
  private static final SecurityInfosPath DATA_GROUP_HASH = new SecurityInfosPath("DATA_GROUP_HASH", "30", 0,
                                                                                 null);

  /**
   * Path to <code>dataGroupNumber</code> of <code>DataGroupHash</code> block.
   */
  public static final SecurityInfosPath DATA_GROUP_HASH_NUMBER = new SecurityInfosPath(
                                                                                       "DATA_GROUP_HASH_NUMBER",
                                                                                       "02", 0,
                                                                                       DATA_GROUP_HASH,
                                                                                       ASN1Integer.class);

  /**
   * Path to <code>dataGroupHashValue</code> of <code>DataGroupHash</code> block.
   */
  public static final SecurityInfosPath DATA_GROUP_HASH_VALUE = new SecurityInfosPath(
                                                                                      "DATA_GROUP_HASH_VALUE",
                                                                                      "04", 0,
                                                                                      DATA_GROUP_HASH);

  /**
   * Path to <code>PSPublicKeyInfo</code> block. Note: there are typically several security info blocks in the
   * file (in undetermined order), therefore it is not possible to connect this path to the root path and it
   * should not be called directly.
   */
  private static final SecurityInfosPath PS_PUBLIC_KEY_INFO = new SecurityInfosPath("PS_PUBLIC_KEY_INFO",
                                                                                    "30", 0, null);

  /**
   * Path to <code>requiredData</code> of <code>PSPublicKeyInfo</code> block.
   */
  private static final SecurityInfosPath PS_PUBLIC_KEY_INFO_REQ_DATA = new SecurityInfosPath(
                                                                                            "PS_PUBLIC_KEY_INFO_REQ_DATA",
                                                                                            "30", 0,
                                                                                            PS_PUBLIC_KEY_INFO);

  /**
   * Path to <code>psPublicKey</code> of <code>requiredData</code> of <code>PSPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath PS_PUBLIC_KEY_INFO_REQ_DATA_PS_PK = new SecurityInfosPath(
                                                                                                  "PS_PUBLIC_KEY_INFO_REQ_DATA_PS_PK",
                                                                                                  "30",
                                                                                                  0,
                                                                                                  PS_PUBLIC_KEY_INFO_REQ_DATA,
                                                                                                  SubjectPublicKeyInfo.class);

  /**
   * Path to <code>optionalData</code> of <code>PSPublicKeyInfo</code> block.
   */
  private static final SecurityInfosPath PS_PUBLIC_KEY_INFO_OPT_DATA = new SecurityInfosPath(
                                                                                            "PS_PUBLIC_KEY_INFO_OPT_DATA",
                                                                                            "30", 1,
                                                                                            PS_PUBLIC_KEY_INFO);

  /**
   * Path to <code>psParameterID</code> of <code>requiredData</code> of <code>PSPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath PS_PUBLIC_KEY_INFO_OPT_DATA_PS_PARAM_ID = new SecurityInfosPath(
                                                                                                        "PS_PUBLIC_KEY_INFO_OPT_DATA_PS_PARAM_ID",
                                                                                                        "81",
                                                                                                        0,
                                                                                                        PS_PUBLIC_KEY_INFO_OPT_DATA,
                                                                                                        ASN1Integer.class);

  /**
   * Path to <code>keyID</code> of <code>requiredData</code> of <code>PSPublicKeyInfo</code> block.
   */
  public static final SecurityInfosPath PS_PUBLIC_KEY_INFO_OPT_DATA_KEY_ID = new SecurityInfosPath(
                                                                                                   "PS_PUBLIC_KEY_INFO_OPT_DATA_KEY_ID",
                                                                                                   "82",
                                                                                                   0,
                                                                                                   PS_PUBLIC_KEY_INFO_OPT_DATA,
                                                                                                   ASN1Integer.class);

  /**
   * Path to <code>PSInfo</code> block. This block does not occur directly, but in three versions:
   * <code>PSAInfo</code>, <code>PSMInfo</code> and <code>PSCInfo</code>, which are structurally identical and
   * differ only by their OID. Note: there are typically several security info blocks in the file (in
   * undetermined order), therefore it is not possible to connect this path to the root path and it should not
   * be called directly.
   */
  private static final SecurityInfosPath PS_INFO = new SecurityInfosPath("PS_INFO", "30", 0, null);

  /**
   * Path to <code>requiredData</code> of <code>PSInfo</code> block.
   */
  private static final SecurityInfosPath PS_INFO_REQUIRED_DATA = new SecurityInfosPath(
                                                                                      "PS_INFO_REQUIRED_DATA",
                                                                                      "30", 0, PS_INFO);

  /**
   * Path to <code>version</code> of <code>requiredData</code> of <code>PSInfo</code> block.
   */
  public static final SecurityInfosPath PS_INFO_REQUIRED_DATA_VERSION = new SecurityInfosPath(
                                                                                              "PS_INFO_REQUIRED_DATA_VERSION",
                                                                                              "02",
                                                                                              0,
                                                                                              PS_INFO_REQUIRED_DATA,
                                                                                              ASN1Integer.class);

  /**
   * Path to <code>ps1-authInfo</code> of <code>requiredData</code> of <code>PSInfo</code> block.
   */
  public static final SecurityInfosPath PS_INFO_REQUIRED_DATA_PS1_AUTH_INFO = new SecurityInfosPath(
                                                                                                    "PS_INFO_REQUIRED_DATA_PS1_AUTH_INFO",
                                                                                                    "02",
                                                                                                    1,
                                                                                                    PS_INFO_REQUIRED_DATA,
                                                                                                    ASN1Integer.class);

  /**
   * Path to <code>ps2-authInfo</code> of <code>requiredData</code> of <code>PSInfo</code> block.
   */
  public static final SecurityInfosPath PS_INFO_REQUIRED_DATA_PS2_AUTH_INFO = new SecurityInfosPath(
                                                                                                    "PS_INFO_REQUIRED_DATA_PS2_AUTH_INFO",
                                                                                                    "02",
                                                                                                    2,
                                                                                                    PS_INFO_REQUIRED_DATA,
                                                                                                    ASN1Integer.class);

  /**
   * Path to <code>keyID</code> of <code>PSInfo</code> block.
   */
  public static final SecurityInfosPath PS_INFO_KEY_ID = new SecurityInfosPath("PS_INFO_KEY_ID", "02", 0,
                                                                               PS_INFO, ASN1Integer.class);

  /**
   * Path to <code>PasswordInfo</code> block. Note: there are typically several security info blocks in the
   * file (in undetermined order), therefore it is not possible to connect this path to the root path and it
   * should not be called directly.
   */
  private static final SecurityInfosPath PASSWORD_INFO = new SecurityInfosPath("PASSWORD_INFO", "30", 0, null);

  /**
   * Path to <code>requiredData</code> of <code>PasswordInfo</code> block.
   */
  private static final SecurityInfosPath PASSWORD_INFO_REQUIRED_DATA = new SecurityInfosPath(
                                                                                            "PASSWORD_INFO_REQUIRED_DATA",
                                                                                            "30", 0,
                                                                                            PASSWORD_INFO);

  /**
   * Path to <code>pwdID</code> of <code>requiredData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_REQUIRED_DATA_PWD_ID = new SecurityInfosPath(
                                                                                                   "PASSWORD_INFO_REQUIRED_DATA_PWD_ID",
                                                                                                   "02",
                                                                                                   0,
                                                                                                   PASSWORD_INFO_REQUIRED_DATA,
                                                                                                   ASN1Integer.class);

  /**
   * Path to <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  private static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA = new SecurityInfosPath(
                                                                                            "PASSWORD_INFO_OPTIONAL_DATA",
                                                                                            "30", 1,
                                                                                            PASSWORD_INFO);

  /**
   * Path to <code>resuming-Pwds</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_RESUMING_PWDS = new SecurityInfosPath(
                                                                                                          "PASSWORD_INFO_OPTIONAL_DATA_RESUMING_PWDS",
                                                                                                          "80",
                                                                                                          0,
                                                                                                          PASSWORD_INFO_OPTIONAL_DATA);

  /**
   * Path to <code>resetting-Pwds</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_RESETTING_PWDS = new SecurityInfosPath(
                                                                                                           "PASSWORD_INFO_OPTIONAL_DATA_RESETTING_PWDS",
                                                                                                           "81",
                                                                                                           0,
                                                                                                           PASSWORD_INFO_OPTIONAL_DATA);

  /**
   * Path to <code>changing-PwdsUT</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_CHANGING_PWDS = new SecurityInfosPath(
                                                                                                          "PASSWORD_INFO_OPTIONAL_DATA_CHANGING_PWDS",
                                                                                                          "82",
                                                                                                          0,
                                                                                                          PASSWORD_INFO_OPTIONAL_DATA);

  /**
   * Path to <code>pwdType</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_PWD_TYPE = new SecurityInfosPath(
                                                                                                     "PASSWORD_INFO_OPTIONAL_DATA_PWD_TYPE",
                                                                                                     "83",
                                                                                                     0,
                                                                                                     PASSWORD_INFO_OPTIONAL_DATA,
                                                                                                     ASN1Integer.class);

  /**
   * Path to <code>minLength</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_MIN_LENGTH = new SecurityInfosPath(
                                                                                                       "PASSWORD_INFO_OPTIONAL_DATA_MIN_LENGTH",
                                                                                                       "84",
                                                                                                       0,
                                                                                                       PASSWORD_INFO_OPTIONAL_DATA,
                                                                                                       ASN1Integer.class);

  /**
   * Path to <code>storedLength</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_STORED_LENGTH = new SecurityInfosPath(
                                                                                                          "PASSWORD_INFO_OPTIONAL_DATA_STORED_LENGTH",
                                                                                                          "85",
                                                                                                          0,
                                                                                                          PASSWORD_INFO_OPTIONAL_DATA,
                                                                                                          ASN1Integer.class);

  /**
   * Path to <code>maxLength</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_MAX_LENGTH = new SecurityInfosPath(
                                                                                                       "PASSWORD_INFO_OPTIONAL_DATA_MAX_LENGTH",
                                                                                                       "86",
                                                                                                       0,
                                                                                                       PASSWORD_INFO_OPTIONAL_DATA,
                                                                                                       ASN1Integer.class);

  /**
   * Path to <code>padChar</code> of <code>optionalData</code> of <code>PasswordInfo</code> block.
   */
  public static final SecurityInfosPath PASSWORD_INFO_OPTIONAL_DATA_PAD_CHAR = new SecurityInfosPath(
                                                                                                     "PASSWORD_INFO_OPTIONAL_DATA_PAD_CHAR",
                                                                                                     "87", 0,
                                                                                                     PASSWORD_INFO_OPTIONAL_DATA);
}
