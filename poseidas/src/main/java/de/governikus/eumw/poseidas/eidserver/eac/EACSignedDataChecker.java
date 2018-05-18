/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.eac;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.SignedDataChecker;


/**
 * Modified code from the mCard. Checks a reply from the EID process and verifies if the certificate used to
 * sign the travel document is a trustworthy one from the master list.
 *
 * @author Ole Behrens
 */
@SuppressWarnings({"unchecked"})
public class EACSignedDataChecker extends EACSignedDataParser implements SignedDataChecker
{
  private static final String CHECK_FAILED = "Exception during check of EF.CardSecurity";

  private static final Log LOG = LogFactory.getLog(EACSignedDataChecker.class.getName());

  private static final String CERTIFICATE_X509 = "X.509";

  private final List<X509Certificate> masterList;

  private boolean masterListChecked;

  /**
   * Instance needs master list
   *
   * @param masterList the master list of all trusted certificates
   */
  public EACSignedDataChecker(List<X509Certificate> masterList, String logPrefix)
  {
    super(logPrefix);
    // Do a copy to avoid that the list is changed externally
    this.masterList = new LinkedList<>(masterList);
  }

  /** {@inheritDoc} */
  @Override
  public boolean checkSignedData(byte[] data)
  {
    if (checkSignedDataInternal(data))
    {
      LOG.debug(logPrefix + "Result: Check OK ");
      return true;
    }
    else
    {
      LOG.debug(logPrefix + "Result: Check NEGATIVE ");
      return false;
    }
  }

  /**
   * Checks data from card for master list:<br/>
   * <ul>
   * <li>Verify digest</li>
   * <li>Master list certificate self signed or part of chain</li>
   * <li>Verify certificate</li>
   * <li>Verify signature</li>
   * </ul>
   *
   * @param data to be validated
   * @return true if check is positive
   */
  private boolean checkSignedDataInternal(byte[] data)
  {
    try
    {
      // First check existing master list
      checkMasterList();

      SignedData signedDataFromCard = getSignedData(data);

      // Get signature security debugmations from content
      ASN1 octetString = new ASN1(signedDataFromCard.getContentInfo()
                                                    .getContent()
                                                    .toASN1Primitive()
                                                    .getEncoded());
      SecurityInfos securitydebugmationsFromCard = new SecurityInfos(octetString.getValue());
      LOG.debug(logPrefix + "Signature security debugmation: "
                + securitydebugmationsFromCard.toString(false));

      // Collect certificates from signed data
      Enumeration<ASN1Sequence> certs = signedDataFromCard.getCertificates().getObjects();
      if (!certs.hasMoreElements())
      {
        LOG.debug(logPrefix + "No certificate found in signature data from card to check signature");
        return false;
      }
      List<Certificate> certifacteListFromCardSignatureData = new ArrayList<>();
      // Handle X509 certificates
      CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_X509,
                                                                      BouncyCastleProvider.PROVIDER_NAME);
      while (certs.hasMoreElements())
      {
        ASN1Sequence nextElement = certs.nextElement();
        ByteArrayInputStream bais = new ByteArrayInputStream(nextElement.getEncoded());

        certifacteListFromCardSignatureData.add(certFactory.generateCertificate(bais));
      }
      // Card certificates collected
      LOG.debug(logPrefix + "Found " + certifacteListFromCardSignatureData.size()
                + " certificate(s) on card");

      // Get signature debugmations
      Enumeration<ASN1Sequence> signatureInfosFromCard = signedDataFromCard.getSignerInfos().getObjects();
      // Need a signature to check
      if (!signatureInfosFromCard.hasMoreElements())
      {
        LOG.debug(logPrefix + "No signature found in data from card to check card");
        return false;
      }
      int signaturesChecked = 0;
      while (signatureInfosFromCard.hasMoreElements())
      {
        signaturesChecked++;
        if (signaturesChecked == 2)
        {
          LOG.debug(logPrefix + "Warning: Found multiple signatures to be checked for this card");
        }
        // Check next signature info
        ASN1Sequence thisSignatureInfoElement = signatureInfosFromCard.nextElement();
        SignerInfo thisSignatureInfo = new SignerInfo(thisSignatureInfoElement);
        ASN1Set thisSignatureAuthenticatedAttributes = thisSignatureInfo.getAuthenticatedAttributes();
        Enumeration<ASN1Sequence> allAttributesFromThisInfo = thisSignatureAuthenticatedAttributes.getObjects();

        // Get signature debugmation digests
        List<byte[]> validDigestsFromThisCardInfoAttributes = new ArrayList<>();
        while (allAttributesFromThisInfo.hasMoreElements())
        {
          Attribute attribute = new Attribute(allAttributesFromThisInfo.nextElement());
          if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_messageDigest))
          {
            byte[] add = ByteUtil.subbytes(attribute.getAttrValues()
                                                    .getObjectAt(0)
                                                    .toASN1Primitive()
                                                    .getEncoded(),
                                           2);
            validDigestsFromThisCardInfoAttributes.add(add);
          }
        }
        if (validDigestsFromThisCardInfoAttributes.isEmpty())
        {
          LOG.debug(logPrefix + "No valid digest found for signature from card info attributes");
          return false;
        }
        LOG.debug(logPrefix + "Found " + validDigestsFromThisCardInfoAttributes.size()
                  + " digest(s) in signature attributes from card");

        // FINGERPRINT CHECK
        // Digest from signature debugmation
        String digestAlgorithm = thisSignatureInfo.getDigestAlgorithm().getAlgorithm().toString();
        MessageDigest infoDigest = MessageDigest.getInstance(digestAlgorithm);
        // Calculate signature digest
        byte[] selfCalculatedDigest = infoDigest.digest(securitydebugmationsFromCard.getEncoded());
        boolean cardSignatureMatch = false;
        for ( byte[] compare : validDigestsFromThisCardInfoAttributes )
        {
          if (Arrays.equals(compare, selfCalculatedDigest))
          {
            cardSignatureMatch = true;
            break;
          }
        }
        // Check if calculated and stored digest match
        if (!cardSignatureMatch)
        {
          LOG.debug(logPrefix + "Digests of signatures do not match");
          return false;
        }
        LOG.debug(logPrefix + "RESULT: Signature digest is valid");


        // CERTIFICATE CHECK
        // Get certificate debugmations from received signature
        IssuerAndSerialNumber signaturedebugmations = thisSignatureInfo.getIssuerAndSerialNumber();
        X500Name signatureCertificateIssuer = signaturedebugmations.getName();
        ASN1Integer signatureCertificateSerialNumber = signaturedebugmations.getCertificateSerialNumber();
        List<Certificate> validCertificates = new ArrayList<>();
        for ( Certificate check : certifacteListFromCardSignatureData )
        {
          org.bouncycastle.asn1.x509.Certificate certStructure = org.bouncycastle.asn1.x509.Certificate.getInstance(check.getEncoded());
          if (certStructure.getIssuer().equals(signatureCertificateIssuer)
              && certStructure.getSerialNumber().equals(signatureCertificateSerialNumber))
          {
            validCertificates.add(check);
          }
          else
          {
            LOG.debug(logPrefix + "WARNING:"
                      + " Signature data and certificate from card do not match issuer debugmations");
          }
        }
        if (validCertificates.isEmpty())
        {
          LOG.debug(logPrefix + "No certificate fits issuer: " + signatureCertificateIssuer.toString()
                    + " and serial: " + signatureCertificateSerialNumber.toString());
          return false;
        }
        LOG.debug(logPrefix + "Certificates and signature data result: " + validCertificates.size() + "/"
                  + certifacteListFromCardSignatureData.size());

        List<Certificate> certificatesOnMasterList = new ArrayList<>();
        for ( Certificate certificate : validCertificates )
        {
          // Check if a certificate is on master list
          if (isCertificateOnMasterList(certificate.getEncoded()))
          {
            LOG.debug(logPrefix + "Certificate is on master list");
            certificatesOnMasterList.add(certificate);
          }
          else
          {
            LOG.debug(logPrefix + "Certificate is not on list: " + certificate);
          }
        }
        if (certificatesOnMasterList.isEmpty())
        {
          LOG.debug(logPrefix + "No certificate is on masterlist: verification negative result");
          return false;
        }

        // SIGNATURE CHECK
        // Calculate signature and verify
        byte[] signatureFromSignatureInfo = thisSignatureInfo.getEncryptedDigest().getOctets();
        String signatureAlgorithmForEncryption = thisSignatureInfo.getDigestEncryptionAlgorithm()
                                                                  .getAlgorithm()
                                                                  .toString();
        byte[] signatureAttributesEncoded = thisSignatureAuthenticatedAttributes.getEncoded();
        boolean signatureVerified = false;
        for ( Certificate initialCertificate : certificatesOnMasterList )
        {
          Signature signature = Signature.getInstance(signatureAlgorithmForEncryption,
                                                      BouncyCastleProvider.PROVIDER_NAME);
          signature.initVerify(initialCertificate);
          signature.update(signatureAttributesEncoded);
          if (signature.verify(signatureFromSignatureInfo))
          {
            signatureVerified = true;
          }
          else
          {
            LOG.debug(logPrefix + "Calculated signature is invalid for this certificate");
            continue;
          }
        }
        if (signatureVerified)
        {
          LOG.debug(logPrefix + "RESULT: Card signature is valid");
        }
        else
        {
          LOG.debug(logPrefix + "Signature is not valid");
          return false;
        }
      }
    }
    catch (IOException e)
    {
      LOG.error(logPrefix + CHECK_FAILED, e);
      return false;
    }
    catch (GeneralSecurityException e)
    {
      LOG.error(logPrefix + CHECK_FAILED, e);
      return false;
    }
    return true;
  }

  /**
   * Initial check for the master list
   *
   * @throws IOException if no master list data are available
   */
  private void checkMasterList() throws IOException
  {
    if (!masterListChecked)
    {
      if (masterList == null)
      {
        throw new IOException("MasterList is null: No check could be done for card");
      }
      if (masterList.isEmpty())
      {
        throw new IOException("MasterList is empty: No check could be done for card");
      }
      masterListChecked = true;
    }
  }

  /**
   * Checks if a certificate from master list is valid
   *
   * @param certificate to be checked
   * @throws IOException if no chain could be build
   */
  private void checkMasterListCertificate(X509Certificate certificate) throws IOException
  {
    if (!isSelfSignedMasterListCertificate(certificate))
    {
      LOG.debug(logPrefix + "NOTE: Self signed certificate in master list is not expected");
    }
  }

  /**
   * Checks if the given certificate found in the client signature data is part of a certificate on the master
   * list.
   *
   * @param certificateToCheck an encoded version of a certificate
   * @return true if the given certificate is in the masterList
   * @throws CertificateException if no X509 certificate is available
   * @throws IOException
   * @throws GeneralSecurityException
   */
  private boolean isCertificateOnMasterList(byte certificateToCheck[])
    throws IOException, GeneralSecurityException
  {
    CertificateFactory fac = CertificateFactory.getInstance(CERTIFICATE_X509,
                                                            BouncyCastleProvider.PROVIDER_NAME);
    ByteArrayInputStream bais = new ByteArrayInputStream(certificateToCheck);
    X509Certificate x509CertificateToCheck = (X509Certificate)fac.generateCertificate(bais);
    X500Principal certificateSubject = x509CertificateToCheck.getSubjectX500Principal();
    X500Principal certificateIssuer = x509CertificateToCheck.getIssuerX500Principal();

    // For all certificates on master list
    LOG.debug(logPrefix + "Try to find issuer certificate for card certificate:\n  "
              + certificateSubject.toString());
    for ( X509Certificate masterCert : masterList )
    {
      if (x509CertificateToCheck.equals(masterCert))
      {
        // Direct matching of certificate: Should only happen for test-EPAs
        LOG.debug(logPrefix + "[CARD CERTIFICATE] Warning:"
                  + " Certificate from card is self signed certificate and also direct on master list");
        return true;
      }
      else
      {
        X500Principal masterCertificateSubject = masterCert.getSubjectX500Principal();
        // Check if issuer from card equals certificate subject from master list
        if (certificateIssuer.equals(masterCertificateSubject))
        {
          checkMasterListCertificate(masterCert);
          x509CertificateToCheck.verify(masterCert.getPublicKey());
          LOG.debug(logPrefix + "RESULT: Verify certificate against master list successful");
          return true;
        }
        else
        {
          LOG.debug(logPrefix + "Found issuers do not match: " + certificateIssuer.toString() + " =! "
                    + masterCertificateSubject.toString());
        }
      }
    }
    // No match found
    return false;
  }

  /**
   * Checks if a certificate from master list is self-signed
   *
   * @param certificate to be checked
   * @return true if certificate is self-signed, false if not
   * @throws IOException if no chain could be build
   */
  private boolean isSelfSignedMasterListCertificate(X509Certificate certificate) throws IOException
  {
    if (certificate == null)
    {
      throw new IOException("Certificate to check is null");
    }
    X500Principal issuer = certificate.getIssuerX500Principal();
    X500Principal subject = certificate.getSubjectX500Principal();
    LOG.debug(logPrefix + "Check master list certificate [" + (masterList.indexOf(certificate) + 1) + "]:\n  "
              + subject.toString() + " " + certificate.getSerialNumber());
    if (issuer.equals(subject))
    {
      return true;
    }
    else
    {
      LOG.debug(logPrefix + "Warning: Found a certificate on master list not self-signed");
      boolean foundIssuer = false;
      // Check master list for issuer for certificate
      for ( X509Certificate isIssuer : masterList )
      {
        // Get the subject of actual certificate to check
        X500Principal issuerSubject = isIssuer.getSubjectX500Principal();
        // Check if this certificate is the searched one
        if (issuerSubject.equals(issuer))
        {
          // Found the issuer for the certificate on list
          foundIssuer = true;
          // Check if certificate could be verified for this issuer
          try
          {
            certificate.verify(isIssuer.getPublicKey());
          }
          catch (GeneralSecurityException e)
          {
            throw new IOException("Certificate on master list could not be verified", e);
          }
          // Check if this certificate is self signed
          checkMasterListCertificate(isIssuer);
          break;
        }
      }

      if (foundIssuer)
      {
        return false;
      }
      else
      {
        throw new IOException("Certificate on list is not self-signed"
                              + " and no issuer could be found to verify");
      }
    }
  }
}
