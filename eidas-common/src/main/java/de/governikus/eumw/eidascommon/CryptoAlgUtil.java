package de.governikus.eumw.eidascommon;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import lombok.experimental.UtilityClass;


/**
 * Utility class for cryptographic algorithm lookup.
 */
@UtilityClass
public class CryptoAlgUtil
{

  private final String EC = "EC";

  private final String RSA = "RSA";

  private final String SHA_256_PATTERN = "^SHA-?256";

  private final String SHA_384_PATTERN = "^SHA-?384";

  private final String SHA_512_PATTERN = "^SHA-?512";

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
    if (digestAlg.matches(SHA_256_PATTERN))
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA256;
    }
    else if (digestAlg.matches(SHA_384_PATTERN))
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA384;
    }
    else if (digestAlg.matches(SHA_512_PATTERN))
    {
      return SignatureConstants.ALGO_ID_DIGEST_SHA512;
    }
    else
    {
      throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                         + USE_SHA256_SHA384_OR_SHA512);
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
        if (digestAlg.matches(SHA_256_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
        }
        if (digestAlg.matches(SHA_384_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1;
        }
        if (digestAlg.matches(SHA_512_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1;
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
      case EC:
        if (digestAlg.matches(SHA_256_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
        }
        if (digestAlg.matches(SHA_384_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384;
        }
        if (digestAlg.matches(SHA_512_PATTERN))
        {
          return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512;
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
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
        if (digestAlg.matches(SHA_256_PATTERN))
        {
          return "SHA256withRSAandMGF1";
        }
        if (digestAlg.matches(SHA_384_PATTERN))
        {
          return "SHA384withRSAandMGF1";
        }
        if (digestAlg.matches(SHA_512_PATTERN))
        {
          return "SHA512withRSAandMGF1";
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
      case EC:
        if (digestAlg.matches(SHA_256_PATTERN))
        {
          return "SHA256withECDSA";
        }
        if (digestAlg.matches(SHA_384_PATTERN))
        {
          return "SHA384withECDSA";
        }
        if (digestAlg.matches(SHA_512_PATTERN))
        {
          return "SHA512withECDSA";
        }
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
      default:
        throw new IllegalArgumentException("Unsupported key algorithm " + keyAlg + ", use RSA or EC");
    }
  }
}
