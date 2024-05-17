package de.governikus.eumw.poseidas.server.pki;

import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.RuntimeOperatorException;

import lombok.AllArgsConstructor;


/**
 * This class provides interoperability between the BouncyCastle provider and the SunPKCS11 provider. <br>
 * The necessary signature algorithm "ecdsa-plain-SHA256" with the OID "0.4.0.127.0.7.1.1.4.1.3" is known under
 * different names in the BC provider and in the SunPKCS11 provider. This class provides the PKCS11 algorithm name to
 * the PKCS11 provider to compute the signature while the BC algorithm name is given to BC to add the correct OID to the
 * CMS object.
 */
@AllArgsConstructor
public class Pkcs11ContentSignerBuilder
{

  /**
   * The PKCS11 provider to sign the data
   */
  private Provider provider;

  /**
   * The PKCS11 private key to sign the data
   */
  private PrivateKey signerKey;

  /**
   * Builds and returns the content signer to sign the CMS object with the ecdsa-plain-SHA256 algorithm
   */
  public ContentSigner build()
  {

    Signature signature;
    try
    {
      signature = Signature.getInstance("SHA256withECDSAinP1363Format", provider);
      signature.initSign(signerKey);
    }
    catch (Exception e)
    {
      throw new RuntimeException(e);
    }


    return new ContentSigner()
    {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier()
      {
        return new AlgorithmIdentifier(BSIObjectIdentifiers.ecdsa_plain_SHA256);
      }

      @Override
      public OutputStream getOutputStream()
      {
        return OutputStreamFactory.createStream(signature);
      }

      @Override
      public byte[] getSignature()
      {
        try
        {
          return signature.sign();
        }
        catch (SignatureException e)
        {
          throw new RuntimeOperatorException("exception creating signature", e);
        }
      }
    };
  }
}
