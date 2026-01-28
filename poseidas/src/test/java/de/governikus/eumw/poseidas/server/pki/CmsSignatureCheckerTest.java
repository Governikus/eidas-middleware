package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;


class CmsSignatureCheckerTest
{



  @Test
  void testValidateCmsSignatureSuccessfullyWithCertSignedByTrustAnchor() throws Exception
  {
    KeyStore trustAnchorKeyStore = getTrustAnchorKeyStore();
    KeyStore signatureKeyStore = getSignatureKeyStore();
    PrivateKey signatureKey = (PrivateKey)signatureKeyStore.getKey("signature-cert", "123456".toCharArray());
    X509Certificate signatureCertificate = (X509Certificate)signatureKeyStore.getCertificate("signature-cert");

    final String rawData = "RAW_DATA_TO_BE_SIGNED";
    byte[] signedCmsData = signData(rawData.getBytes(StandardCharsets.UTF_8), signatureKey, signatureCertificate);

    X509Certificate trustAnchor = (X509Certificate)trustAnchorKeyStore.getCertificate("trust-anchor");
    CmsSignatureChecker cmsSignatureChecker = new CmsSignatureChecker(trustAnchor);
    Assertions.assertDoesNotThrow(() -> cmsSignatureChecker.checkEnvelopedSignature(signedCmsData));
  }


  @Test
  void testValidateCmsSignatureSuccessfullyWithCertReplaced() throws Exception
  {
    KeyStore trustAnchorKeyStore = getTrustAnchorKeyStore();
    KeyStore signatureKeyStore = getSignatureKeyStore();
    PrivateKey signatureKey = (PrivateKey)signatureKeyStore.getKey("signature-cert", "123456".toCharArray());
    X509Certificate signatureCertificate = (X509Certificate)signatureKeyStore.getCertificate("signature-cert");

    final String rawData = "RAW_DATA_TO_BE_SIGNED";
    byte[] signedCmsData = signData(rawData.getBytes(StandardCharsets.UTF_8), signatureKey, signatureCertificate);

    X509Certificate trustAnchor = (X509Certificate)trustAnchorKeyStore.getCertificate("trust-anchor");
    CmsSignatureChecker cmsSignatureChecker = new CmsSignatureChecker(trustAnchor);
    String issuerName = signatureCertificate.getIssuerX500Principal().getName();
    X500Name x509Name = new X500Name(issuerName);
    IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(x509Name,
                                                                            signatureCertificate.getSerialNumber());
    CmsSignatureChecker.CertReplacedRecord certReplacedRecord = new CmsSignatureChecker.CertReplacedRecord(signatureCertificate,
                                                                                                           issuerAndSerialNumber);
    cmsSignatureChecker.setCertReplacedRecord(certReplacedRecord);
    Assertions.assertDoesNotThrow(() -> cmsSignatureChecker.checkEnvelopedSignature(signedCmsData));
  }

  private KeyStore getSignatureKeyStore() throws IOException
  {
    try (InputStream input = getClass().getResourceAsStream("/keys/signature-cert.p12"))
    {
      return KeyStoreSupporter.readKeyStore(input, KeyStoreSupporter.KeyStoreType.PKCS12, "123456");
    }
  }

  private KeyStore getTrustAnchorKeyStore() throws IOException
  {
    try (InputStream input = getClass().getResourceAsStream("/keys/trust-anchor.p12"))
    {
      return KeyStoreSupporter.readKeyStore(input, KeyStoreSupporter.KeyStoreType.PKCS12, "123456");
    }
  }

  static byte[] signData(byte[] data, PrivateKey signingKey, X509Certificate signingCertificate) throws Exception
  {
    CMSTypedData cmsData = new CMSProcessableByteArray(data);
    CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

    if (signingCertificate == null)
    {
      CMSSignedData cms = cmsGenerator.generate(cmsData, true);
      return cms.getEncoded();
    }

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
    DigestCalculatorProvider calculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                                                                                          .build();

    List<X509Certificate> certList = new ArrayList<>();
    certList.add(signingCertificate);
    JcaCertStore jcaCertStore = new JcaCertStore(certList);
    SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(calculatorProvider).build(contentSigner,
                                                                                                          signingCertificate);
    cmsGenerator.addSignerInfoGenerator(signerInfoGenerator);
    cmsGenerator.addCertificates(jcaCertStore);

    CMSSignedData cms = cmsGenerator.generate(cmsData, true);
    return cms.getEncoded();
  }

}
