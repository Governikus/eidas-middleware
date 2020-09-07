/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.X509IssuerName;
import org.opensaml.xmlsec.signature.X509IssuerSerial;
import org.opensaml.xmlsec.signature.X509SerialNumber;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.impl.X509IssuerNameBuilder;
import org.opensaml.xmlsec.signature.impl.X509IssuerSerialBuilder;
import org.opensaml.xmlsec.signature.impl.X509SerialNumberBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;


/**
 * <p>
 * Helper for adding a signature to a SignableXMLObject. Please note that this adds everything except the
 * signature value itself. Make sure to add that after marshalling the XML object. Furthermore, this class can
 * be used for validating the signatures.
 * </p>
 * <p>
 * WARNING: the underlying XML security implementation has a bug which disables signing after verifying with
 * same algorithm in same thread. This class does not contain a work-around for that problem because it does
 * not arise in many scenarios. If necessary, open a new thread for signing!
 * </p>
 * <p>
 * </p>
 *
 * @author TT / AHO
 */
final class XMLSignatureHandler
{

  private static final String SHA_1_PATTERN = "^SHA-?1";

  private static final String SHA_256_PATTERN = "^SHA-?256";

  private static final String SHA_256_PSS_PATTERN = "^SHA-?256-?PSS";

  private static final String SHA_384_PATTERN = "^SHA-?384";

  private static final String SHA_512_PATTERN = "^SHA-?512";

  public static final String GIVEN_DIGEST_ALGORITHM = "Given digest algorithm ";


  /**
   * available kinds of key info
   */
  enum SigEntryType
  {
    /** do not add signature at all */
    NONE,
    /** specify key by giving the certificate */
    CERTIFICATE,
    /** specify key by mentioning certificates issuer and serial number */
    ISSUERSERIAL
  }

  /**
   * Add a signature to a SignableXMLObject. Please note that this adds everything except the signature value
   * itself. Make sure to add that after marshalling the XML object.
   *
   * @param signable object to sign
   * @param key signature key
   * @param cert certificate matching the signature key
   * @param type specifies how to identify the key in the signature
   * @throws CertificateEncodingException
   */
  static void addSignature(SignableXMLObject signable,
                                  PrivateKey key,
                                  X509Certificate cert,
                                  SigEntryType type,
                                  String sigDigestAlg)
    throws CertificateEncodingException
  {
    if (type == SigEntryType.NONE)
    {
      return;
    }

    if (sigDigestAlg == null)
    {
      throw new IllegalArgumentException("Signature Digest Algorithm must not be null.");
    }

    Signature sig = new SignatureBuilder().buildObject();
    BasicX509Credential credential = new BasicX509Credential(cert);
    credential.setPrivateKey(key);
    sig.setSigningCredential(credential);
    String keyAlg = key.getAlgorithm();

    if ("EC".equalsIgnoreCase(keyAlg) || "ECDSA".equalsIgnoreCase(keyAlg))
    {
      checkForECSignatures(sigDigestAlg, sig);
    }
    else if ("RSA".equalsIgnoreCase(keyAlg))
    {
      checkForRSASignatures(sigDigestAlg, sig);
    }
    else if ("DSA".equalsIgnoreCase(keyAlg))
    {
      checkForDSASignatures(sigDigestAlg, sig);
    }
    else
    {
      throw new IllegalArgumentException("Unsupported key algorithm " + keyAlg
                                         + ", use RSA, DSA, ECDSA or EC");
    }
    sig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
    X509Data x509Data = new X509DataBuilder().buildObject();
    if (type == SigEntryType.CERTIFICATE)
    {
      addCertificate(cert, x509Data);
    }
    else if (type == SigEntryType.ISSUERSERIAL)
    {
      addIssuerSerial(cert, x509Data);
    }
    keyInfo.getX509Datas().add(x509Data);
    sig.setKeyInfo(keyInfo);
    signable.setSignature(sig);

    if ("SHA256".equals(sigDigestAlg) || "SHA256-PSS".equals(sigDigestAlg))
    {
      ((SAMLObjectContentReference)sig.getContentReferences()
                                      .get(0)).setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
    }
  }

  private static void checkForDSASignatures(String sigDigestAlg, Signature sig)
  {
    if (sigDigestAlg.matches(SHA_1_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1);
    }
    else
    {
      throw new IllegalArgumentException(GIVEN_DIGEST_ALGORITHM + sigDigestAlg
                                         + " not supported with DSA keys, use SHA1");
    }
  }

  private static void checkForRSASignatures(String sigDigestAlg, Signature sig)
  {
    if (sigDigestAlg.matches(SHA_1_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    }
    else if (sigDigestAlg.matches(SHA_256_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    }
    else if (sigDigestAlg.matches(SHA_256_PSS_PATTERN))
    {
      sig.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    }
    else if (sigDigestAlg.matches(SHA_384_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384);
    }
    else if (sigDigestAlg.matches(SHA_512_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
    }
    else
    {
      throw new IllegalArgumentException(GIVEN_DIGEST_ALGORITHM + sigDigestAlg
                                         + " not supported with RSA keys, use SHA1, SHA256, SHA384 or SHA512");
    }
  }

  private static void checkForECSignatures(String sigDigestAlg, Signature sig)
  {
    if (sigDigestAlg.matches(SHA_1_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
    }
    else if (sigDigestAlg.matches(SHA_256_PATTERN) || sigDigestAlg.matches(SHA_256_PSS_PATTERN))
    // SHA256-PSS at the moment sigDigestAlg will be always SHA256
    {
      sig.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    }
    else if (sigDigestAlg.matches(SHA_384_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384);
    }
    else if (sigDigestAlg.matches(SHA_512_PATTERN))
    {
      sig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512);
    }
    else
    {
      throw new IllegalArgumentException(GIVEN_DIGEST_ALGORITHM + sigDigestAlg + " not supported");
    }
  }

  private static void addCertificate(X509Certificate cert, X509Data data) throws CertificateEncodingException
  {
    org.opensaml.xmlsec.signature.X509Certificate xmlcert = new X509CertificateBuilder().buildObject();
    xmlcert.setValue(DatatypeConverter.printBase64Binary(cert.getEncoded()));
    data.getX509Certificates().add(xmlcert);
  }

  private static void addIssuerSerial(X509Certificate cert, X509Data data)
  {
    X509IssuerSerial is = new X509IssuerSerialBuilder().buildObject();
    X509IssuerName in = new X509IssuerNameBuilder().buildObject();
    in.setValue(cert.getIssuerX500Principal().getName());
    is.setX509IssuerName(in);
    X509SerialNumber se = new X509SerialNumberBuilder().buildObject();
    se.setValue(cert.getSerialNumber());
    is.setX509SerialNumber(se);
    data.getX509IssuerSerials().add(is);
  }

  /**
   * Check the contained signature against a given trusted anchor.
   *
   * @param trustedAnchor
   * @param sig
   * @return the index of the key that was used for the successful check
   */
  static int checkSignature(Signature sig, X509Certificate... trustedAnchor) throws ErrorCodeException
  {
    if (trustedAnchor == null || trustedAnchor.length == 0)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED, "no trusted anchor given");
    }
    if (sig == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_MISSING);
    }

    SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
    try
    {
      profileValidator.validate(sig);
    }
    catch (SignatureException e)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED, e);
    }
    catch (Exception e)
    {
      throw new ErrorCodeException(ErrorCode.INTERNAL_ERROR, e);
    }
    for ( int i = 0 ; i < trustedAnchor.length ; i++ )
    {
      if (trustedAnchor[i] == null)
      {
        continue;
      }
      BasicX509Credential credential = new BasicX509Credential(trustedAnchor[i]);
      credential.setEntityCertificate(trustedAnchor[i]);
      try
      {
        SignatureValidator.validate(sig, credential);

        /* return if we found one matching signature */
        return i;
      }
      catch (SignatureException e)
      {
        /* Nothing to do */
      }
      catch (Exception e)
      {
        throw new ErrorCodeException(ErrorCode.INTERNAL_ERROR, e);
      }
    }
    throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
  }

  private XMLSignatureHandler()
  {}
}
