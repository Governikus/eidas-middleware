package de.governikus.eumw.eidascommon;

import java.util.regex.Pattern;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.xmlsec.signature.DigestMethod;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import lombok.experimental.UtilityClass;


/**
 * Utility class for cryptographic algorithm lookup.
 */
@UtilityClass
public class CryptoAlgUtil
{

  public static final String INVALID_HASH_OR_SIGNATURE_ALGORITHM = "Invalid hash or signature algorithm";

  private final String EC = "EC";

  private final String RSA = "RSA";

  private final Pattern SHA_256_PATTERN = Pattern.compile("^SHA-?256");

  private final Pattern SHA_384_PATTERN = Pattern.compile("^SHA-?384");

  private final Pattern SHA_512_PATTERN = Pattern.compile("^SHA-?512");

  private final String UNSUPPORTED_DIGEST_ALGORITHM = "Unsupported digest algorithm ";

  private final String USE_SHA256_SHA384_OR_SHA512 = ", use SHA256, SHA384 or SHA512";

  /**
   * Gets XML digest algorithm ID for a given digest algorithm name.
   *
   * @param digestAlg digest algorithm name
   * @return XML digest algorithm ID, if supported
   */
  public String toXmlDigestAlgId(String digestAlg)
  {
    if (SHA_256_PATTERN.matcher(digestAlg).matches())
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA256;
    }
    else if (SHA_384_PATTERN.matcher(digestAlg).matches())
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA384;
    }
    else if (SHA_512_PATTERN.matcher(digestAlg).matches())
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA512;
    }
    else
    {
      throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg + USE_SHA256_SHA384_OR_SHA512);
    }
  }

  /**
   * Gets XML signature algorithm ID for a given digest algorithm name and key algorithm name.
   *
   * @param digestAlg digest algorithm name
   * @param keyAlg key algorithm name
   * @return XML signature algorithm ID, if supported
   */
  public String toXmlSigAlgId(String digestAlg, String keyAlg)
  {
    switch (keyAlg)
    {
      case RSA:
        if (SHA_256_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
        }
        if (SHA_384_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1;
        }
        if (SHA_512_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1;
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg + USE_SHA256_SHA384_OR_SHA512);
      case EC:
        if (SHA_256_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
        }
        if (SHA_384_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384;
        }
        if (SHA_512_PATTERN.matcher(digestAlg).matches())
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512;
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg + USE_SHA256_SHA384_OR_SHA512);
      default:
        throw new IllegalArgumentException("Unsupported key algorithm " + keyAlg + ", use RSA or EC");
    }
  }

  /**
   * Gets JCA signature algorithm name for a given digest algorithm name and key algorithm name.
   *
   * @param digestAlg digest algorithm name
   * @param keyAlg key algorithm name
   * @return JCA signature algorithm name, if supported
   */
  public String toJcaSigAlgName(String digestAlg, String keyAlg)
  {
    switch (keyAlg)
    {
      case RSA:
        if (SHA_256_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA256withRSAandMGF1";
        }
        if (SHA_384_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA384withRSAandMGF1";
        }
        if (SHA_512_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA512withRSAandMGF1";
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg + USE_SHA256_SHA384_OR_SHA512);
      case EC:
        if (SHA_256_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA256withECDSA";
        }
        if (SHA_384_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA384withECDSA";
        }
        if (SHA_512_PATTERN.matcher(digestAlg).matches())
        {
          return "SHA512withECDSA";
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg + USE_SHA256_SHA384_OR_SHA512);
      default:
        throw new IllegalArgumentException("Unsupported key algorithm " + keyAlg + ", use RSA or EC");
    }
  }

  public String fromXmlSigAlg(String xmlSigAlgo)
  {
    String algoName;
    switch (xmlSigAlgo)
    {
      case XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1:
        algoName = "SHA256withRSAandMGF1";
        break;
      case XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1:
        algoName = "SHA384withRSAandMGF1";
        break;
      case XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1:
        algoName = "SHA512withRSAandMGF1";
        break;
      case XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256:
        algoName = "SHA256withECDSA";
        break;
      case XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384:
        algoName = "SHA384withECDSA";
        break;
      case XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512:
        algoName = "SHA512withECDSA";
        break;
      default:
        throw new UnsupportedOperationException("unsupported signature algorithm " + xmlSigAlgo);
    }
    return algoName;
  }

  /**
   * Verify that the signature algorithm used to sign an AuthnRequest is permitted
   *
   * @param sigAlg The signature algorithm to be checked
   * @throws ErrorCodeException Thrown if a non-permitted algorithm is used
   */
  public static void verifySignatureAlgorithm(String sigAlg) throws ErrorCodeException
  {
    try
    {
      fromXmlSigAlg(sigAlg);
    }
    catch (Exception e)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED, INVALID_HASH_OR_SIGNATURE_ALGORITHM);
    }
  }

  /**
   * Verify that the signature algorithm and the DigestMethod algorithm of the SAML signature are permitted.
   *
   * @param signature The signature to be verified
   * @throws ErrorCodeException Thrown if a non-permitted algorithm is used
   */
  public static void verifyDigestAndSignatureAlgorithm(Signature signature) throws ErrorCodeException
  {
    // Verify the digest methods of the signature elements are allowed
    // The OpenSAML API does not return the actual digest method, so we must manually get this from the XML document
    NodeList elementsByTagName = signature.getDOM()
                                          .getElementsByTagNameNS(SignatureConstants.XMLSIG_NS,
                                                                  DigestMethod.DEFAULT_ELEMENT_LOCAL_NAME);
    for ( int i = 0 ; i < elementsByTagName.getLength() ; i++ )
    {
      Node digestMethodElement = elementsByTagName.item(i);
      Node algorithmAttribute = digestMethodElement.getAttributes().getNamedItem(DigestMethod.ALGORITHM_ATTRIB_NAME);
      String algorithmUri = algorithmAttribute.getTextContent();
      if (digestAlgorithmNotPermitted(algorithmUri))
      {
        throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED, INVALID_HASH_OR_SIGNATURE_ALGORITHM);
      }
    }

    verifySignatureAlgorithm(signature.getSignatureAlgorithm());
  }

  private static boolean digestAlgorithmNotPermitted(String algorithmUri)
  {
    return !(SignatureConstants.ALGO_ID_DIGEST_SHA256.equals(algorithmUri)
             || SignatureConstants.ALGO_ID_DIGEST_SHA384.equals(algorithmUri)
             || SignatureConstants.ALGO_ID_DIGEST_SHA512.equals(algorithmUri));
  }
}
