package de.governikus.eumw.poseidas.cardserver;

import java.security.cert.X509Certificate;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public final class CertificateUtil
{

  private CertificateUtil()
  {
    // No Instance needed
  }

  /**
   * This predicate takes a certificate <code>A</code> from the lambda function and the value of the X.509
   * extension <code>Authority Key Identifier</code> of certificate <code>B</code>. It then checks, if the
   * <code>Authority Key Identifier</code> of certificate <code>B</code> is equal to the
   * <code>Subject Key Identifier</code> of certificate <code>A</code>.
   */
  public static Predicate<X509Certificate> findIssuerByAuthorityKeyIdentifier(byte[] authorityKeyIdentifier)
  {
    return certificate -> {
      try
      {
        ASN1OctetString asn1OctetString = (ASN1OctetString)ASN1Primitive.fromByteArray(authorityKeyIdentifier);
        ASN1Sequence asn1Sequence = (ASN1Sequence)ASN1Primitive.fromByteArray(asn1OctetString.getOctets());
        ASN1OctetString reference = (ASN1OctetString)((ASN1TaggedObject)asn1Sequence.getObjectAt(0)).getObject();

        ASN1OctetString outerOctetString = (ASN1OctetString)ASN1Primitive.fromByteArray(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        ASN1OctetString actual = (ASN1OctetString)ASN1Primitive.fromByteArray(outerOctetString.getOctets());

        return reference.equals(actual);
      }
      catch (Exception e)
      {
        log.debug("Cannot compare the authority key identifier and subject key identifier", e);
        return false;
      }
    };
  }
}
