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

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.CardInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.EIDSecurityInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PasswordInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PrivilegedTerminalInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.TerminalAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;


/**
 * Implementation of ASN.1 structure for SecurityInfos, contained in EF.CardAccess, EF.CardSecurity and
 * EF.ChipSecurity files.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class SecurityInfos extends AbstractASN1Encoder implements ASN1Encoder
{

  private static final String INCORRECT_ASN_1_OBJECT = "incorrect ASN.1 object";

  /**
   * List of {@link PasswordInfo}
   */
  private List<PasswordInfo> passwordInfoList;

  /**
   * List of {@link PACEInfo}
   */
  private List<PACEInfo> paceInfoList;

  /**
   * List of {@link PACEDomainParameterInfo}
   */
  private List<PACEDomainParameterInfo> paceDomainParameterInfoList;

  /**
   * List of {@link ChipAuthenticationInfo}
   */
  private List<ChipAuthenticationInfo> chipAuthenticationInfoList;

  /**
   * List of {@link ChipAuthenticationDomainParameterInfo}
   */
  private List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList;

  /**
   * List of {@link ChipAuthenticationPublicKeyInfo}
   */
  private List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfoList;

  /**
   * List of {@link TerminalAuthenticationInfo}
   */
  private List<TerminalAuthenticationInfo> terminalAuthenticationList;

  /**
   * List of {@link RestrictedIdentificationInfo}
   */
  private List<RestrictedIdentificationInfo> restrictedIdentificationInfoList;

  /**
   * Reference to {@link RestrictedIdentificationDomainParameterInfo} (no list as there should be only one)
   */
  private RestrictedIdentificationDomainParameterInfo restrictedIdentificationDomainParameterInfo;

  /**
   * Reference to {@link CardInfo} (no list as there should be only one)
   */
  private CardInfo cardInfo;

  /**
   * Reference to {@link EIDSecurityInfo} (no list as there should be only one)
   */
  private EIDSecurityInfo eIDSecurityInfo;

  /**
   * Reference to {@link PrivilegedTerminalInfo} (no list as there should be only one)
   */
  private PrivilegedTerminalInfo privilegedTerminalInfo;

  /**
   * Constructor.
   */
  public SecurityInfos()
  {
    super();
  }

  /**
   * Constructor.
   *
   * @param bytes bytes of ASN.1
   * @throws IOException if constructing fails
   */
  public SecurityInfos(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 getChildElementByPath(ASN1Path part) throws IOException
  {
    if (!SecurityInfosPath.class.isInstance(part))
    {
      throw new IllegalArgumentException("only EFCardAccessPart permitted");
    }
    return super.getChildElementByPath(part);
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 decode(ASN1 asn1)
  {
    if (asn1 == null)
    {
      return null;
    }
    super.copy(asn1);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected void update()
  {
    super.update();
    if (this.paceInfoList == null)
    {
      try
      {
        this.passwordInfoList = new ArrayList<>();
        this.paceInfoList = new ArrayList<>();
        this.paceDomainParameterInfoList = new ArrayList<>();
        this.chipAuthenticationInfoList = new ArrayList<>();
        this.chipAuthenticationDomainParameterInfoList = new ArrayList<>();
        this.chipAuthenticationPublicKeyInfoList = new ArrayList<>();
        this.terminalAuthenticationList = new ArrayList<>();
        this.restrictedIdentificationInfoList = new ArrayList<>();
        for ( ASN1 a : this.getChildElementsByTag(SecurityInfosPath.SECURITY_INFO.getTag()) )
        {
          OID oid = (OID)a.getChildElementByPath(SecurityInfosPath.SECURITY_INFO_PROTOCOL);
          addPasswordInfo(a, oid);
          addPACEInfo(a, oid);
          addPACEDomainParameterInfo(a, oid);
          addChipAuthenticationInfo(a, oid);
          addChipAuthenticationDomainParameterInfo(a, oid);
          addChipAuthenticationPublicKeyInfo(a, oid);
          addTerminalAuthenticationInfo(a, oid);
          addRestrictedAuthenticationInfo(a, oid);
          addRestrictedIdentificationDomainParameterInfo(a, oid);
          setCardInfo(a, oid);
          setEIDSecurityInfo(a, oid);
          setPriviligedTerminalInfo(a, oid);
        }
      }
      catch (IOException e)
      {
        this.passwordInfoList = null;
        this.paceInfoList = null;
        this.paceDomainParameterInfoList = null;
        this.chipAuthenticationInfoList = null;
        this.chipAuthenticationDomainParameterInfoList = null;
        this.chipAuthenticationPublicKeyInfoList = null;
        this.terminalAuthenticationList = null;
        this.restrictedIdentificationInfoList = null;
        throw new IllegalArgumentException("incompatible ASN.1 object", e);
      }
    }
  }

  /**
   * Adds {@link PrivilegedTerminalInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link PrivilegedTerminalInfo} fails
   * @throws IllegalArgumentException if {@link PrivilegedTerminalInfo} previously set
   */
  private void setPriviligedTerminalInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_PTI))
    {
      if (this.privilegedTerminalInfo == null)
      {
        this.privilegedTerminalInfo = new PrivilegedTerminalInfo(a.getEncoded());
      }
      else
      {
        throw new IllegalArgumentException(INCORRECT_ASN_1_OBJECT);
      }
    }
  }

  /**
   * Adds {@link EIDSecurityInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link EIDSecurityInfo} fails
   * @throws IllegalArgumentException if {@link EIDSecurityInfo} previously set
   */
  private void setEIDSecurityInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_ESI))
    {
      if (this.eIDSecurityInfo == null)
      {
        this.eIDSecurityInfo = new EIDSecurityInfo(a.getEncoded());
      }
      else
      {
        throw new IllegalArgumentException(INCORRECT_ASN_1_OBJECT);
      }
    }
  }

  /**
   * Adds {@link CardInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link CardInfo} fails
   * @throws IllegalArgumentException if {@link CardInfo} previously set
   */
  private void setCardInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_CI))
    {
      if (this.cardInfo == null)
      {
        this.cardInfo = new CardInfo(a.getEncoded());
      }
      else
      {
        throw new IllegalArgumentException(INCORRECT_ASN_1_OBJECT);
      }
    }
  }

  /**
   * Adds {@link RestrictedIdentificationDomainParameterInfo} for related {@link ASN1} identified by
   * {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link RestrictedIdentificationDomainParameterInfo} fails
   */
  private void addRestrictedIdentificationDomainParameterInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_RI_DH) || oid.equals(OIDConstants.OID_RI_ECDH))
    {
      this.restrictedIdentificationDomainParameterInfo = new RestrictedIdentificationDomainParameterInfo(a.getEncoded());
    }
  }

  /**
   * Adds {@link RestrictedIdentificationInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link RestrictedIdentificationInfo} fails
   */
  private void addRestrictedAuthenticationInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_RI_DH_SHA_1) || oid.equals(OIDConstants.OID_RI_DH_SHA_224)
        || oid.equals(OIDConstants.OID_RI_DH_SHA_256) || oid.equals(OIDConstants.OID_RI_DH_SHA_384)
        || oid.equals(OIDConstants.OID_RI_DH_SHA_512) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_1)
        || oid.equals(OIDConstants.OID_RI_ECDH_SHA_224) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_256)
        || oid.equals(OIDConstants.OID_RI_ECDH_SHA_384) || oid.equals(OIDConstants.OID_RI_ECDH_SHA_512))
    {
      this.restrictedIdentificationInfoList.add(new RestrictedIdentificationInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link TerminalAuthenticationInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link TerminalAuthenticationInfo} fails
   */
  private void addTerminalAuthenticationInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_TA))
    {
      this.terminalAuthenticationList.add(new TerminalAuthenticationInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link ChipAuthenticationPublicKeyInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link ChipAuthenticationPublicKeyInfo} fails
   */
  private void addChipAuthenticationPublicKeyInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_PK_DH) || oid.equals(OIDConstants.OID_PK_ECDH))
    {
      this.chipAuthenticationPublicKeyInfoList.add(new ChipAuthenticationPublicKeyInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link ChipAuthenticationDomainParameterInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link ChipAuthenticationDomainParameterInfo} fails
   */
  private void addChipAuthenticationDomainParameterInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_CA_DH) || oid.equals(OIDConstants.OID_CA_ECDH))
    {
      this.chipAuthenticationDomainParameterInfoList.add(new ChipAuthenticationDomainParameterInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link ChipAuthenticationInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link ChipAuthenticationInfo} fails
   */
  private void addChipAuthenticationInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_CA_DH_3DES_CBC_CBC) || oid.equals(OIDConstants.OID_CA_DH_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_CA_DH_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_CA_DH_AES_CBC_CMAC_256)
        || oid.equals(OIDConstants.OID_CA_ECDH_3DES_CBC_CBC)
        || oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_CA_ECDH_AES_CBC_CMAC_256))
    {
      this.chipAuthenticationInfoList.add(new ChipAuthenticationInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link PACEDomainParameterInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link PACEDomainParameterInfo} fails
   */
  private void addPACEDomainParameterInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_PACE_DH_GM) || oid.equals(OIDConstants.OID_PACE_ECDH_GM)
        || oid.equals(OIDConstants.OID_PACE_DH_IM) || oid.equals(OIDConstants.OID_PACE_ECDH_IM))
    {
      this.paceDomainParameterInfoList.add(new PACEDomainParameterInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link PasswordInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link PasswordInfo} fails
   */
  private void addPasswordInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_PASSWORD_TYPE_PIN) || oid.equals(OIDConstants.OID_PASSWORD_TYPE_CAN)
        || oid.equals(OIDConstants.OID_PASSWORD_TYPE_PUK) || oid.equals(OIDConstants.OID_PASSWORD_TYPE_MRZ))
    {
      this.passwordInfoList.add(new PasswordInfo(a.getEncoded()));
    }
  }

  /**
   * Adds {@link PACEInfo} for related {@link ASN1} identified by {@link OID}.
   *
   * @param a asn1
   * @param oid oid
   * @throws IOException if creating {@link PACEInfo} fails
   */
  private void addPACEInfo(ASN1 a, OID oid) throws IOException
  {
    if (oid.equals(OIDConstants.OID_PACE_DH_GM_3DES_CBC_CBC)
        || oid.equals(OIDConstants.OID_PACE_DH_GM_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_PACE_DH_GM_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_PACE_DH_GM_AES_CBC_CMAC_256)
        || oid.equals(OIDConstants.OID_PACE_ECDH_GM_3DES_CBC_CBC)
        || oid.equals(OIDConstants.OID_PACE_ECDH_GM_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_PACE_ECDH_GM_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_PACE_ECDH_GM_AES_CBC_CMAC_256)
        || oid.equals(OIDConstants.OID_PACE_DH_IM_3DES_CBC_CBC)
        || oid.equals(OIDConstants.OID_PACE_DH_IM_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_PACE_DH_IM_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_PACE_DH_IM_AES_CBC_CMAC_256)
        || oid.equals(OIDConstants.OID_PACE_ECDH_IM_3DES_CBC_CBC)
        || oid.equals(OIDConstants.OID_PACE_ECDH_IM_AES_CBC_CMAC_128)
        || oid.equals(OIDConstants.OID_PACE_ECDH_IM_AES_CBC_CMAC_192)
        || oid.equals(OIDConstants.OID_PACE_ECDH_IM_AES_CBC_CMAC_256))
    {
      this.paceInfoList.add(new PACEInfo(a.getEncoded()));
    }
  }

  /**
   * Gets a list of all {@link PasswordInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link PasswordInfo}, can be <code>null</code> or empty
   */
  public List<PasswordInfo> getPasswordInfo()
  {
    return this.passwordInfoList;
  }

  /**
   * Gets a list of all {@link PACEInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link PACEInfo}, can be <code>null</code> or empty
   */
  public List<PACEInfo> getPACEInfo()
  {
    return this.paceInfoList;
  }

  /**
   * Gets a list of all {@link PACEDomainParameterInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link PACEDomainParameterInfo}, can be <code>null</code> or empty
   */
  public List<PACEDomainParameterInfo> getPACEDomainParameterInfo()
  {
    return this.paceDomainParameterInfoList;
  }

  /**
   * Gets a list of all {@link ChipAuthenticationInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link ChipAuthenticationInfo}, can be <code>null</code> or empty
   */
  public List<ChipAuthenticationInfo> getChipAuthenticationInfo()
  {
    return this.chipAuthenticationInfoList;
  }

  /**
   * Gets a list of all {@link ChipAuthenticationDomainParameterInfo} structures in this {@link SecurityInfos}
   * .
   *
   * @return list of {@link ChipAuthenticationDomainParameterInfo}, can be <code>null</code> or empty
   */
  public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfo()
  {
    return this.chipAuthenticationDomainParameterInfoList;
  }

  /**
   * Gets a list of all {@link ChipAuthenticationPublicKeyInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link ChipAuthenticationPublicKeyInfo}, can be <code>null</code> or empty
   */
  public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfo()
  {
    return this.chipAuthenticationPublicKeyInfoList;
  }

  /**
   * Gets a list of all {@link TerminalAuthenticationInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link TerminalAuthenticationInfo}, can be <code>null</code> or empty
   */
  public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfo()
  {
    return this.terminalAuthenticationList;
  }

  /**
   * Gets a list of all {@link RestrictedIdentificationInfo} structures in this {@link SecurityInfos}.
   *
   * @return list of {@link RestrictedIdentificationInfo}, can be <code>null</code> or empty
   */
  public List<RestrictedIdentificationInfo> getRestrictedIdentificationInfo()
  {
    return this.restrictedIdentificationInfoList;
  }

  /**
   * Gets the {@link RestrictedIdentificationDomainParameterInfo} structure in this {@link SecurityInfos}.
   *
   * @return the {@link RestrictedIdentificationDomainParameterInfo}, can be <code>null</code>
   */
  public RestrictedIdentificationDomainParameterInfo getRestrictedIdentificationDomainParameterInfo()
  {
    return this.restrictedIdentificationDomainParameterInfo;
  }

  /**
   * Gets the {@link CardInfo} structure in this {@link SecurityInfos}.
   *
   * @return the {@link CardInfo}, can be <code>null</code>
   */
  public CardInfo getCardInfo()
  {
    return this.cardInfo;
  }

  /**
   * Gets the {@link EIDSecurityInfo} structure in this {@link SecurityInfos}.
   *
   * @return the {@link EIDSecurityInfo}, can be <code>null</code>
   */
  public EIDSecurityInfo getEIDSecurityInfo()
  {
    return this.eIDSecurityInfo;
  }

  /**
   * Gets the {@link PrivilegedTerminalInfo} structure in this {@link SecurityInfos}.
   *
   * @return the {@link PrivilegedTerminalInfo}, can be <code>null</code>
   */
  public PrivilegedTerminalInfo getPrivilegedTerminalInfo()
  {
    return this.privilegedTerminalInfo;
  }


  private static BigInteger bigIntfromHex(String hexString)
  {
    return new BigInteger(hexString, 16);
  }

  private static ECParameterSpec createSpec(String prime, String a, String b, String x, String y, String n)
  {
    ECFieldFp field = new ECFieldFp(bigIntfromHex(prime));
    EllipticCurve curve = new EllipticCurve(field, bigIntfromHex(a), bigIntfromHex(b));
    ECPoint point = new ECPoint(bigIntfromHex(x), bigIntfromHex(y));
    return new ECParameterSpec(curve, point, bigIntfromHex(n), 1);
  }

  private static final ECParameterSpec BRAINPOOL_P192R1 = createSpec("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
                                                                     "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
                                                                     "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
                                                                     "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
                                                                     "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
                                                                     "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1");

  private static final ECParameterSpec BRAINPOOL_P224R1 = createSpec("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
                                                                     "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
                                                                     "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
                                                                     "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
                                                                     "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
                                                                     "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F");

  private static final ECParameterSpec BRAINPOOL_P256R1 = createSpec("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                                                                     "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
                                                                     "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
                                                                     "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
                                                                     "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
                                                                     "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");

  private static final ECParameterSpec BRAINPOOL_P320R1 = createSpec("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
                                                                     "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
                                                                     "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
                                                                     "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
                                                                     "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
                                                                     "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311");

  private static final ECParameterSpec BRAINPOOL_P384R1 = createSpec("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
                                                                     "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
                                                                     "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
                                                                     "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
                                                                     "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
                                                                     "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565");

  private static final ECParameterSpec BRAINPOOL_P512R1 = createSpec("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                                                                     "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
                                                                     "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
                                                                     "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
                                                                     "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
                                                                     "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069");

  private static final ECParameterSpec SECP192R1 = createSpec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                                                              "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
                                                              "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                                                              "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");

  private static final ECParameterSpec SECP224R1 = createSpec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
                                                              "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
                                                              "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
                                                              "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");

  private static final ECParameterSpec SECP256R1 = createSpec("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                                                              "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                                                              "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                                                              "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                                                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                                                              "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

  private static final ECParameterSpec SECP384R1 = createSpec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
                                                              "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
                                                              "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                                                              "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
                                                              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");

  private static final ECParameterSpec SECP521R1 = createSpec("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                                                              "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
                                                              "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
                                                              "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
                                                              "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
                                                              "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");

  /**
   * Map for domain parameter IDs and domain parameters (see TR-03110 v2.04).
   */
  private static final Map<Integer, ECParameterSpec> DOMAIN_PARAMETER_MAP = new HashMap<>();
  static
  {
    DOMAIN_PARAMETER_MAP.put(8, SECP192R1);
    DOMAIN_PARAMETER_MAP.put(9, BRAINPOOL_P192R1);
    DOMAIN_PARAMETER_MAP.put(10, SECP224R1);
    DOMAIN_PARAMETER_MAP.put(11, BRAINPOOL_P224R1);
    DOMAIN_PARAMETER_MAP.put(12, SECP256R1);
    DOMAIN_PARAMETER_MAP.put(13, BRAINPOOL_P256R1);
    DOMAIN_PARAMETER_MAP.put(14, BRAINPOOL_P320R1);
    DOMAIN_PARAMETER_MAP.put(15, SECP384R1);
    DOMAIN_PARAMETER_MAP.put(16, BRAINPOOL_P384R1);
    DOMAIN_PARAMETER_MAP.put(17, BRAINPOOL_P512R1);
    DOMAIN_PARAMETER_MAP.put(18, SECP521R1);
  }

  /**
   * Gets unmodifiable version of domain parameter map.
   *
   * @return domain parameter map
   */
  public static Map<Integer, ECParameterSpec> getDomainParameterMap()
  {
    return Collections.unmodifiableMap(DOMAIN_PARAMETER_MAP);
  }

  @Override
  public boolean equals(Object object)
  {
    return super.equals(object);
  }

  @Override
  public int hashCode()
  {
    return super.hashCode();
  }
}
