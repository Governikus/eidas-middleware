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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of CertificateDescription.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Slf4j
public class CertificateDescription extends AbstractASN1Encoder
{

  /**
   * Sets OID.
   *
   * @param oid OID as String, normally "0.4.0.127.0.7.3.1.3.1" as defined at TC-03110 (version 2.02) in
   *          appendix C.3.1, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#DESCRIPTION_TYPE
   */
  public final synchronized void setOID(String oid) throws IOException
  {
    AssertUtil.notNull(oid, "OID");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.DESCRIPTION_TYPE), null);
    this.addChildElement(new OID(oid), null);
  }

  /**
   * Sets subject.
   *
   * @param subject subject, encoded as UTF-8, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#SUBJECT_NAME_PART
   * @see CertificateDescriptionPath#SUBJECT_NAME
   */
  public final synchronized void setSubject(String subject) throws IOException
  {
    AssertUtil.notNull(subject, "subject");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.SUBJECT_NAME_PART), null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.SUBJECT_NAME_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.SUBJECT_NAME.getTag().toByteArray(),
                                           subject.getBytes(StandardCharsets.UTF_8)).getEncoded()), null);
  }

  /**
   * Sets subject URL.
   *
   * @param subjectURL subject URL, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#SUBJECT_URL_PART
   * @see CertificateDescriptionPath#SUBJECT_URL
   */
  public final synchronized void setSubjectURL(String subjectURL) throws IOException
  {
    AssertUtil.notNull(subjectURL, "subject URL");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.SUBJECT_URL_PART), null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.SUBJECT_URL_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.SUBJECT_URL.getTag().toByteArray(),
                                           subjectURL.getBytes(StandardCharsets.UTF_8)).getEncoded()), null);
  }

  /**
   * Sets issuer.
   *
   * @param issuer issuer, encoded as UTF-8, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#ISSUER_NAME_PART
   * @see CertificateDescriptionPath#ISSUER_NAME
   */
  public final synchronized void setIssuer(String issuer) throws IOException
  {
    AssertUtil.notNull(issuer, "issuer");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.ISSUER_NAME_PART), null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.ISSUER_NAME_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.ISSUER_NAME.getTag().toByteArray(),
                                           issuer.getBytes(StandardCharsets.UTF_8)).getEncoded()), null);
  }

  /**
   * Sets issuer URL.
   *
   * @param issuerURL issuer URL, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#ISSUER_URL_PART
   * @see CertificateDescriptionPath#ISSUER_URL
   */
  public final synchronized void setIssuerURL(String issuerURL) throws IOException
  {
    AssertUtil.notNull(issuerURL, "issuer URL");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.ISSUER_URL_PART), null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.ISSUER_URL_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.ISSUER_URL.getTag().toByteArray(),
                                           issuerURL.getBytes(StandardCharsets.UTF_8)).getEncoded()), null);
  }

  /**
   * Sets redirect URL.
   *
   * @param redirectURL redirect URL, <code>null</code> not permitted
   * @throws UnsupportedOperationException if adding child not supported
   * @throws IOException if internal recoding fails
   * @throws IllegalArgumentException if argument <code>null</code>
   * @see CertificateDescriptionPath#REDIRECT_URL_PART
   * @see CertificateDescriptionPath#REDIRECT_URL
   */
  public final synchronized void setRedirectURL(String redirectURL) throws IOException
  {
    AssertUtil.notNull(redirectURL, "redirect URL");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.REDIRECT_URL_PART), null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.REDIRECT_URL_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.REDIRECT_URL.getTag().toByteArray(),
                                           redirectURL.getBytes(StandardCharsets.UTF_8)).getEncoded()), null);
  }

  /**
   * Sets communication certificates.
   *
   * @param commCertificates byte-array containing subsequent ASN.1-encoded octet strings, each of which is
   *          the hash of one communication certificate, <code>null</code> or empty not permitted
   * @throws UnsupportedOperationException
   * @throws IOException
   * @throws IllegalArgumentException if argument <code>null</code> or empty
   */
  public final synchronized void setCommCertificates(byte[] commCertificates)
    throws IOException
  {
    AssertUtil.notNullOrEmpty(commCertificates, "communication certificate hashes");
    super.removeChildElement(this.getChildElementByPath(CertificateDescriptionPath.COMM_CERTIFICATES_PART),
                             null);
    this.addChildElement(new ASN1(CertificateDescriptionPath.COMM_CERTIFICATES_PART.getTag().toByteArray(),
                                  new ASN1(CertificateDescriptionPath.COMM_CERTIFICATES.getTag()
                                                                                       .toByteArray(),
                                           commCertificates).getEncoded()), null);
  }

  /**
   * Constructor using bytes of ASN.1 (already full encoding).
   *
   * @param bytes bytes of ASN.1
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(byte[])
   * @see CertificateDescriptionPath
   * @see CertificateDescriptionPath#getTag()
   * @see CertificateDescriptionPath#CERTIFICATE_DESCRIPTION
   */
  public CertificateDescription(byte[] bytes) throws IOException
  {
    super(bytes);
    check();
  }

  /**
   * Checks if object really represents certificate description.
   *
   * @throws IllegalArgumentException if check fails
   */
  private void check()
  {
    if (!Arrays.equals(CertificateDescriptionPath.CERTIFICATE_DESCRIPTION.getTag().toByteArray(),
                       this.getDTagBytes()))
    {
      throw new IllegalArgumentException("ASN.1 does not represent a certificate description");
    }
  }

  /** {@inheritDoc} */
  @Override
  public final ASN1 getChildElementByPath(ASN1Path part) throws IOException
  {
    if (!CertificateDescriptionPath.class.isInstance(part))
    {
      throw new IllegalArgumentException("only CertificateDescriptionPath permitted");
    }
    return super.getChildElementByPath(part);
  }

  /**
   * Gets part of CertificateDescription by path.
   *
   * @param path path to part
   * @return part of ASN.1 if found, otherwise <code>null</code>
   * @throws IOException if fails
   * @see ASN1#getChildElementByPath(ASN1Path)
   */
  public ASN1 getCertificateDescriptionPart(CertificateDescriptionPath path) throws IOException
  {
    return super.getChildElementByPath(path);
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 decode(byte[] bytes) throws IOException
  {
    AssertUtil.notNullOrEmpty(bytes, "bytes");
    ASN1 cd = new ASN1(bytes);
    super.decode(cd);
    return this;
  }

  /**
   * Hashes a certificate description.
   *
   * @param rootCert root CVC (provides algorithm to be used), <code>null</code> not permitted
   * @param cd certificate description to be hashed, <code>null</code> not permitted
   * @return hash value
   * @throws IllegalArgumentException if any argument <code>null</code>
   * @throws IOException
   * @throws NoSuchAlgorithmException
   */
  public static byte[] hashCertDescription(ECCVCertificate rootCert, CertificateDescription cd)
    throws IOException, NoSuchAlgorithmException
  {
    AssertUtil.notNull(rootCert, "root CVC");
    AssertUtil.notNull(cd, "certificate description");

    OID oid = new OID(rootCert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_OID).getEncoded());
    MessageDigest md = DigestUtil.getDigestByOID(oid);
    return md.digest(cd.getEncoded());
  }

  public String getIssuerName()
  {
    return getString(CertificateDescriptionPath.ISSUER_NAME);
  }

  public String getIssuerUrl()
  {
    return getString(CertificateDescriptionPath.ISSUER_URL);
  }

  public String getSubjectName()
  {
    return getString(CertificateDescriptionPath.SUBJECT_NAME);
  }

  public String getSubjectUrl()
  {
    return getString(CertificateDescriptionPath.SUBJECT_URL);
  }

  public String getRedirectUrl()
  {
    return getString(CertificateDescriptionPath.REDIRECT_URL);
  }

  public String getTermsOfUsagePlainText()
  {
    return getString(CertificateDescriptionPath.TERMS_OF_USAGE_PLAIN_TEXT);
  }

  public String getTermsOfUsageHTML()
  {
    return getString(CertificateDescriptionPath.TERMS_OF_USAGE_HTML);
  }

  public byte[] getTermsOfUsagePDF()
  {
    try
    {
      ASN1 certificateDescriptionPart = getCertificateDescriptionPart(CertificateDescriptionPath.TERMS_OF_USAGE_PDF);
      return certificateDescriptionPart == null ? null : certificateDescriptionPart.getValue();
    }
    catch (IOException e)
    {
      throw new RuntimeException("Can not read certificate description", e);
    }
  }

  public List<byte[]> getCommunicationCertificateHashes()
  {
    List<byte[]> result = new ArrayList<>();
    try
    {
      ASN1 certificateDescriptionPart = getCertificateDescriptionPart(CertificateDescriptionPath.COMM_CERTIFICATES);
      if (certificateDescriptionPart == null)
      {
        return result;
      }
      if (certificateDescriptionPart.isSet())
      {
        ASN1[] childElements = certificateDescriptionPart.getChildElements();
        for ( ASN1 child : childElements )
        {
          result.add(child.getValue());
        }
      }
      else
      {
        result.add(certificateDescriptionPart.getValue());
      }
    }
    catch (IOException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Can not read certificate description", e);
      }
      // nothing
    }
    return result;
  }

  private String getString(CertificateDescriptionPath subjectName)
  {
    try
    {
      ASN1 certificateDescriptionPart = getCertificateDescriptionPart(subjectName);
      if (certificateDescriptionPart != null && certificateDescriptionPart.getValue() != null)
      {
        return new String(certificateDescriptionPart.getValue(), StandardCharsets.UTF_8);
      }
      else
      {
        return null;
      }
    }
    catch (IOException e)
    {
      throw new RuntimeException("Can not read certificate description", e);
    }
  }

  @Override
  public String toString()
  {
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("  ISSUER_NAME = ").append(getIssuerName()).append("\n");
    stringBuilder.append("  ISSUER_URL = ").append(getIssuerUrl()).append("\n");
    stringBuilder.append("  SUBJECT_NAME = ").append(getSubjectName()).append("\n");
    stringBuilder.append("  SUBJECT_URL = ").append(getSubjectUrl()).append("\n");
    stringBuilder.append("  TERMS_OF_USAGE_PLAIN_TEXT = ").append(getTermsOfUsagePlainText()).append("\n");
    stringBuilder.append("  TERMS_OF_USAGE_HTML = ").append(getTermsOfUsageHTML()).append("\n");
    return stringBuilder.toString();
  }
}
