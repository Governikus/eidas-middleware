package de.governikus.eumw.eidascommon;

import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import lombok.experimental.UtilityClass;

import java.util.regex.Pattern;


/**
 * Utility class for cryptographic algorithm lookup.
 */
@UtilityClass
public class CryptoAlgUtil
{

  private final String EC = "EC";

  private final String RSA = "RSA";

  private final Pattern SHA_256_PATTERN = Pattern.compile("^SHA-?256");

  private final Pattern SHA_384_PATTERN =  Pattern.compile("^SHA-?384");

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
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
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
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
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
        throw new IllegalArgumentException(UNSUPPORTED_DIGEST_ALGORITHM + digestAlg
                                           + USE_SHA256_SHA384_OR_SHA512);
      default:
        throw new IllegalArgumentException("Unsupported key algorithm " + keyAlg + ", use RSA or EC");
    }
  }
}
