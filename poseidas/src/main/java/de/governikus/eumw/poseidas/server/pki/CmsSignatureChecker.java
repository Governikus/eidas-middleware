/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.SecurityProvider;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * used to verify the signature of a CMS data block
 * <p>
 * Copyright &copy; 2009-2020 Governikus GmbH &amp; Co. KG
 * </p>
 *
 * @author Pascal Knüppel
 * @since 02.06.2021
 */
@Slf4j
public class CmsSignatureChecker
{

  /**
   * the trust anchor that is the base certificate that must be used to verify all other certificates that
   * have been used for signing within the cms-data lock
   */
  private final Set<X509Certificate> trustAnchors = new HashSet<>();

  private final Set<String> acceptedDigestAlgs = new HashSet<>();

  private final Set<String> acceptedSigAlgs = new HashSet<>();

  private final Set<String> acceptedCurves = new HashSet<>();

  /** holds the signed content after successful verification */
  @Getter
  private Object verifiedContent;

  /** holds the certificate after successful verification */
  @Getter
  private Certificate verifierCertificate;

  /**
   * Holds the string representation of the OID associated with the encapsulated content info structure
   * carried in the signed data.
   */
  @Getter
  private String signedContentTypeOID;


  public CmsSignatureChecker(X509Certificate trustAnchor)
  {
    this.trustAnchors.add(Objects.requireNonNull(trustAnchor));
  }

  public CmsSignatureChecker(Collection<X509Certificate> trustAnchors)
  {
    this.trustAnchors.addAll(Objects.requireNonNull(trustAnchors));
  }

  /**
   * Constructor allowing configuration of accepted cryptographic algorithms.
   * 
   * @param trustAnchors trust anchor certificates, <code>null</code> not permitted
   * @param digestAlgs accepted digest algorithms as OID strings, <code>null</code> or empty for accepting any digest
   * @param sigAlgs accepted signature algorithms as OID strings, <code>null</code> or empty for accepting any algorithm
   * @param curves accepted elliptic curves as names, <code>null</code> or empty for accepting any curve
   */
  public CmsSignatureChecker(Collection<X509Certificate> trustAnchors,
                             Collection<String> digestAlgs,
                             Collection<String> sigAlgs,
                             Collection<String> curves)
  {
    this.trustAnchors.addAll(Objects.requireNonNull(trustAnchors));
    this.acceptedDigestAlgs.addAll(Objects.requireNonNullElse(digestAlgs, Set.of()));
    this.acceptedSigAlgs.addAll(Objects.requireNonNullElse(sigAlgs, Set.of()));
    this.acceptedCurves.addAll(Objects.requireNonNullElse(curves, Set.of()));
  }

  /**
   * checks the signature of the signed data and checks the validity of the certificates by validating them
   * against the current trust anchor
   *
   * @param signedCmsData the signed data to validate. This data itself contains the certificates that must be
   *          used to validate the signature. The trust anchor is used to check if the certificates are valid
   * @throws CMSException if the given datablock is not valid CMS data
   */
  public void checkEnvelopedSignature(byte[] signedCmsData) throws CMSException, SignatureException
  {
    checkEnvelopedSignature(signedCmsData, null);
  }

  /**
   * checks the signature of the signed data and checks the validity of the certificates by validating them
   * against the current trust anchor
   *
   * @param signedCmsData the signed data to validate. This data itself contains the certificates that must be
   *          used to validate the signature. The trust anchor is used to check if the certificates are valid
   * @throws CMSException if the given datablock is not valid CMS data
   */
  public void checkEnvelopedSignature(InputStream signedCmsData) throws CMSException, SignatureException
  {
    checkEnvelopedSignature(signedCmsData, null);
  }

  /**
   * checks the signature of the signed data and checks the validity of the certificates by validating them
   * against the current trust anchor
   *
   * @param signedCmsData the signed data to validate. This data itself contains the certificates that must be
   *          used to validate the signature. The trust anchor is used to check if the certificates are valid
   * @param crlService CRLService to check revocation status, check will not be performed if <code>null</code>
   *          given
   * @throws CMSException if the given datablock is not valid CMS data
   */
  public void checkEnvelopedSignature(byte[] signedCmsData, CertificationRevocationListImpl crlService)
    throws CMSException, SignatureException
  {
    // ByteArrayInputStreams do not need to be closed, so don't worry
    checkEnvelopedSignature(new ByteArrayInputStream(signedCmsData), crlService);
  }

  private void checkEnvelopedSignature(InputStream signedCmsData, CertificationRevocationListImpl crlService)
    throws CMSException, SignatureException
  {
    CMSSignedData cmsSignedData = new CMSSignedData(signedCmsData);
    SignerInformationStore signers = cmsSignedData.getSignerInfos();
    if (signers.getSigners().isEmpty())
    {
      throw new SignatureException("No signing information present within signed data");
    }
    Store<X509CertificateHolder> certificateStorage = cmsSignedData.getCertificates();
    for ( SignerInformation signer : signers.getSigners() )
    {
      if (!acceptedDigestAlgs.isEmpty() && !acceptedDigestAlgs.contains(signer.getDigestAlgOID()))
      {
        throw new SignatureException("Unsupported digest algorithm detected");
      }
      if (!acceptedSigAlgs.isEmpty() && !acceptedSigAlgs.contains(signer.getEncryptionAlgOID()))
      {
        throw new SignatureException("Unsupported signature algorithm detected");
      }

      @SuppressWarnings("unchecked")
      X509CertificateHolder holder = (X509CertificateHolder)certificateStorage.getMatches(signer.getSID())
                                                                              .iterator()
                                                                              .next();
      ByteArrayInputStream certInputStream = getInputStreamOfCertificateData(holder);
      X509Certificate signatureVerificationCertificate = KeyReader.readX509Certificate(certInputStream);

      if (!acceptedCurves.isEmpty() && "EC".equals(signatureVerificationCertificate.getPublicKey().getAlgorithm()))
      {
        byte[] paramsFromCert;
        try
        {
          paramsFromCert = holder.getSubjectPublicKeyInfo()
                                 .getAlgorithm()
                                 .getParameters()
                                 .toASN1Primitive()
                                 .getEncoded();
        }
        catch (IOException e)
        {
          throw new SignatureException("Unable to extract curve parameters from certificate", e);
        }

        boolean found = acceptedCurves.stream().map(c -> {
          try
          {
            return ECNamedCurveTable.getByName(c).getEncoded();
          }
          catch (IOException e)
          {
            if (log.isDebugEnabled())
            {
              log.debug("Failed to get EC curve from certificate", e);
            }
            return null;
          }
        }).anyMatch(b -> ByteUtil.equals(b, paramsFromCert));
        if (!found)
        {
          throw new SignatureException("Unsupported elliptic curve detected");
        }
      }

      validateCertificate(signatureVerificationCertificate, crlService);

      PublicKey publicKey = signatureVerificationCertificate.getPublicKey();
      SignerInformationVerifier signerInformationVerifier = getSignerInformationVerifier(publicKey);
      boolean isSignatureValid = signer.verify(signerInformationVerifier);
      if (!isSignatureValid)
      {
        throw new SignatureException("Signature verification of CMS data failed.");
      }
      verifierCertificate = signatureVerificationCertificate;
    }
    signedContentTypeOID = cmsSignedData.getSignedContentTypeOID();
    verifiedContent = cmsSignedData.getSignedContent().getContent();
  }

  /**
   * tries to build a signer information verifier with the given public key
   *
   * @param publicKey the public key that should be used to verify the CMS signature
   * @return the signer information verifier
   */
  private SignerInformationVerifier getSignerInformationVerifier(PublicKey publicKey)
    throws SignatureException
  {
    try
    {
      return new JcaSimpleSignerInfoVerifierBuilder().setProvider(SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                                                     .build(publicKey);
    }
    catch (OperatorCreationException e)
    {
      final String b64EncodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
      throw new SignatureException(String.format("Failed to build signer information verifier with given public "
                                                 + "key: %s",
                                                 b64EncodedKey),
                                   e);
    }
  }

  /**
   * tries to get a byte-stream from the given certificate
   *
   * @param holder the certificate data
   * @return the input stream
   */
  private ByteArrayInputStream getInputStreamOfCertificateData(X509CertificateHolder holder)
    throws SignatureException
  {
    byte[] certificateData;
    try
    {
      certificateData = holder.getEncoded();
    }
    catch (IOException e)
    {
      throw new SignatureException("Cannot get bytes of signature certificate", e);
    }
    return new ByteArrayInputStream(certificateData);
  }

  /**
   * checks if the given certificate was issued by the {@link #trustAnchors} certificate
   */
  private void validateCertificate(X509Certificate verificationCertificate,
                                   CertificationRevocationListImpl crl)
    throws SignatureException
  {
    if (crl != null)
    {
      if (crl.isOnCRL(verificationCertificate))
      {
        throw new SignatureException("verification certificate found on CRL");
      }
    }

    final boolean isTrustAnchorItself = trustAnchors.contains(verificationCertificate);
    if (isTrustAnchorItself)
    {
      return;
    }
    Optional<X509Certificate> trustAnchor;
    // Try to find the issuer with the Authority Key Identifier
    trustAnchor = trustAnchors.stream()
                              .filter(CertificateUtil.findIssuerByAuthorityKeyIdentifier(verificationCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId())))
                              .findAny();
    // If this did not find an issuer, try to find it using the Issuer DN
    if (!trustAnchor.isPresent())
    {
      X500Principal verificationCertIssuer = verificationCertificate.getIssuerX500Principal();
      trustAnchor = trustAnchors.stream()
                                .filter(cert -> cert.getSubjectX500Principal().equals(verificationCertIssuer))
                                .findAny();
    }
    // If there is still no trustAnchor, we must abort
    if (!trustAnchor.isPresent())
    {
      throw new SignatureException(String.format("Certificate for subject '%s' is not issued by any of the "
                                                 + "trustanchors but by issuer '%s'",
                                                 verificationCertificate.getSubjectDN().toString(),
                                                 verificationCertificate.getIssuerDN().toString()));
    }

    if (crl != null && crl.isOnCRL(trustAnchor.get()))
    {
      throw new SignatureException("trust anchor certificate found on CRL");
    }

    try
    {
      verificationCertificate.verify(trustAnchor.get().getPublicKey());
    }
    catch (GeneralSecurityException e)
    {
      throw new SignatureException(String.format("Certificate for subject '%s' was not signed by "
                                                 + "trustanchor '%s'",
                                                 verificationCertificate.getSubjectDN().toString(),
                                                 trustAnchor.get().getSubjectDN().toString()),
                                   e);
    }
  }
}
