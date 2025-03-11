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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;


/**
 * Implementation of ECCVCertificate.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class ECCVCertificate extends AbstractASN1Encoder
{

  /**
   * Error message to use when given ASN.1 structure is not a CVC.
   */
  private static final String ERROR_MESSAGE_NO_CVC = "ASN.1 does not represent a CV certificate";

  private static final Log LOGGER = LogFactory.getLog(ECCVCertificate.class.getName());

  private Date expirationDate;

  private Date effectiveDate;

  private String holderReference;

  private String caReference;

  private byte[] profileIdentifier;

  private ECPublicKey publicKey;

  private CertificateHolderAuthorizationTemplate chat;

  private byte[] sectorPublicKeyHash;

  /**
   * Constructor.
   *
   * @param bytes bytes of complete CVC, <code>null</code> or empty not permitted
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if bytes <code>null</code> or empty or if bytes contain structure not
   *           complying with CVC structure.
   * @see ASN1#ASN1(byte[])
   */
  public ECCVCertificate(byte[] bytes) throws IOException
  {
    super(bytes);
    this.update();
  }

  /**
   * Checks if CVC structure requirements are fulfilled.
   *
   * @throws IllegalArgumentException if requirements not fulfilled
   */
  @Override
  public void update()
  {
    this.profileIdentifier = null;
    this.caReference = null;
    this.publicKey = null;
    this.holderReference = null;
    this.chat = null;
    this.effectiveDate = null;
    this.expirationDate = null;
    this.sectorPublicKeyHash = null;

    if (!Arrays.equals(ECCVCPath.CV_CERTIFICATE.getTag().toByteArray(), this.getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
    }

    try
    {
      List<ASN1> bodyChildList = checkBody();

      if (!Arrays.equals(ECCVCPath.PROFILE_IDENTIFIER.getTag().toByteArray(),
                         bodyChildList.get(0).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.profileIdentifier = bodyChildList.get(0).getValue();

      if (!Arrays.equals(ECCVCPath.CA_REFERENCE.getTag().toByteArray(), bodyChildList.get(1).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.caReference = new String(bodyChildList.get(1).getValue(), StandardCharsets.UTF_8);

      if (!Arrays.equals(ECCVCPath.PUBLIC_KEY.getTag().toByteArray(), bodyChildList.get(2).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.publicKey = new ECPublicKey(bodyChildList.get(2).getEncoded());

      if (!Arrays.equals(ECCVCPath.HOLDER_REFERENCE.getTag().toByteArray(),
                         bodyChildList.get(3).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.holderReference = new String(bodyChildList.get(3).getValue(), StandardCharsets.UTF_8);

      if (!Arrays.equals(ECCVCPath.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.getTag().toByteArray(),
                         bodyChildList.get(4).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.chat = new CertificateHolderAuthorizationTemplate(bodyChildList.get(4).getEncoded());

      if (!Arrays.equals(ECCVCPath.EFFECTIVE_DATE.getTag().toByteArray(),
                         bodyChildList.get(5).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      this.effectiveDate = this.getDate(bodyChildList.get(5).getValue());

      if (!Arrays.equals(ECCVCPath.EXPIRATION_DATE.getTag().toByteArray(),
                         bodyChildList.get(6).getDTagBytes()))
      {
        throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
      }
      Date date = this.getDate(bodyChildList.get(6).getValue());
      Calendar calendar = Calendar.getInstance();
      calendar.setTime(date);
      calendar.add(Calendar.HOUR, 24);
      this.expirationDate = calendar.getTime();
    }
    catch (IOException | ParseException e)
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC, e);
    }

    ASN1 tsH1 = null;
    ASN1 tsH2 = null;
    try
    {
      tsH1 = this.getCVCPart(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_FIRST_HASH);
    }
    catch (IOException e)
    {
      if (LOGGER.isDebugEnabled())
      {
        LOGGER.debug("Failed to get cvc: " + e.getMessage());
      }
      // nothing
    }
    try
    {
      tsH2 = this.getCVCPart(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_SECOND_HASH);
    }
    catch (IOException e)
    {
      if (LOGGER.isDebugEnabled())
      {
        LOGGER.debug("Failed to get cvc: " + e.getMessage());
      }
      // nothing
    }
    ASN1[] values = new ASN1[]{tsH1, tsH2};
    for ( ASN1 key : values )
    {
      if (key != null)
      {
        this.sectorPublicKeyHash = key.getValue();
        return;
      }
    }
  }

  private List<ASN1> checkBody() throws IOException
  {
    List<ASN1> childList = this.getChildElementList();
    if (childList.size() != 2)
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
    }
    if (!Arrays.equals(ECCVCPath.CV_CERTIFICATE_BODY.getTag().toByteArray(), childList.get(0).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
    }
    if (!Arrays.equals(ECCVCPath.SIGNATURE.getTag().toByteArray(), childList.get(1).getDTagBytes()))
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
    }
    List<ASN1> bodyChildList = childList.get(0).getChildElementList();
    if (bodyChildList.size() != 7 && bodyChildList.size() != 8)
    {
      throw new IllegalArgumentException(ERROR_MESSAGE_NO_CVC);
    }
    return bodyChildList;
  }

  /**
   * Gets child element by given path.
   *
   * @param path path to child element, <code>null</code> not permitted, must be instance of {@link ECCVCPath}
   *          .
   * @return child element of ASN.1 specified by path, uses subclass of {@link ASN1} if given in path object,
   *         <code>null</code>, if not found
   * @throws IOException if reading fails
   * @throws IllegalArgumentException if requested path <code>null</code> or if path not instance of
   *           {@link ECCVCPath}
   */
  @Override
  public ASN1 getChildElementByPath(ASN1Path path) throws IOException
  {
    if (!ECCVCPath.class.isInstance(path))
    {
      throw new IllegalArgumentException("only ECCVCPath permitted");
    }
    return super.getChildElementByPath(path);
  }

  /**
   * Gets part of ECCVCertificate by path.
   *
   * @param path path to part, <code>null</code> not permitted
   * @return child element of ASN.1 specified by path, uses subclass of {@link ASN1} if given in path object,
   *         <code>null</code>, if not found
   * @throws IOException if fails
   * @throws IllegalArgumentException if path <code>null</code>
   * @see ASN1#getChildElementByPath(ASN1Path)
   */
  public ASN1 getCVCPart(ECCVCPath path) throws IOException
  {
    return super.getChildElementByPath(path);
  }

  /**
   * Decoding not enabled for this type.
   */
  @Override
  public ASN1 decode(byte[] bytes)
  {
    throw new IllegalStateException("change not enabled");
  }

  /**
   * Decoding not enabled for this type.
   */
  @Override
  public ASN1 decode(ASN1 asn1)
  {
    throw new IllegalStateException("change not enabled");
  }

  public ECPublicKey getPublicKey()
  {
    return this.publicKey;
  }

  public String getHolderReferenceString()
  {
    return this.holderReference;
  }

  public String getAuthorityReferenceString()
  {
    return this.caReference;
  }

  public byte[] getProfileIdentifier()
  {
    return this.profileIdentifier;
  }

  /**
   * This method returns not the actual value from the ASN.1 structure of the CVC, but the value from the ASN.1
   * structure of the CVC plus 24 hours. The actual value of the expiration date from the ASN.1 structure of a CVC is
   * the date after which the certificate expires. See TR 3110-3.
   *
   * @return the date when the cvc is expired
   */
  public Date getExpirationDateDate()
  {
    return this.expirationDate;
  }

  public Date getEffectiveDateDate()
  {
    return this.effectiveDate;
  }

  public CertificateHolderAuthorizationTemplate getChat()
  {
    return this.chat;
  }

  /**
   * the hash of the public sector key, necessary for the EID service to query the matching sector public key
   * of the certificate used for restricted identification.
   *
   * @return the SectorPublicKeyHash or null
   */
  public byte[] getSectorPublicKeyHash()
  {
    return this.sectorPublicKeyHash == null ? null : this.sectorPublicKeyHash;
  }

  public byte[] getPublicSector1Hash() throws IOException
  {
    return getPublicSectorElement(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_FIRST_HASH);
  }

  public byte[] getPublicSector2Hash() throws IOException
  {
    return getPublicSectorElement(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_TERMINAL_SECTOR_RI_SECOND_HASH);
  }

  private byte[] getPublicSectorElement(ECCVCPath path) throws IOException
  {
    ASN1 element = getChildElementByPath(path);
    return element == null ? null : element.getValue();
  }

  private Date getDate(byte[] dateByte) throws IOException, ParseException
  {
    if (dateByte == null || dateByte.length != 6)
    {
      throw new IOException("date in unknown format");
    }
    String dateString = "20" + dateByte[0] + dateByte[1] + dateByte[2] + dateByte[3] + dateByte[4]
                        + dateByte[5];
    SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd");
    df.setTimeZone(TimeZone.getTimeZone("UTC"));
    return df.parse(dateString);
  }

  /**
   * Check if the Hash of the CVCdescription inside the CVC matches the actual hash of the given
   * CVCDescription.
   *
   * @param cvcDescription
   * @return true if equals false if not or the data structures are corrupt
   */
  public boolean checkCVCDescriptionHash(CertificateDescription cvcDescription)
  {
    try
    {
      byte[] hashCertDescription = CertificateDescription.hashCertDescription(this, cvcDescription);
      byte[] certificateDescriptionHash = this.getChildElementByPath(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION_HASH)
                                              .getValue();
      return MessageDigest.isEqual(certificateDescriptionHash, hashCertDescription);
    }
    catch (IllegalArgumentException | GeneralSecurityException | IOException e)
    {
      // This only happens if one part of the input is malformed,
      // which should be checked inside the constructor before
      // returning false should result in a comprehensive user message
      LOGGER.info("can't compare CVC description hashes: " + e.getMessage(), e);
      return false;
    }
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
