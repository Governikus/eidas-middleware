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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import de.governikus.eumw.eidasstarterkit.XMLSignatureHandler.SigEntryType;
import lombok.Getter;


/**
 * @author hohnholt
 */
@Getter
public class EidasSigner
{

  private static final String SAML_SIGNING = "samlsigning";

  private static final String DIGEST_DEFAULT = "SHA256";

  /**
   * signature key
   */
  private final PrivateKey sigKey;

  /**
   * signature certificate
   */
  private final X509Certificate sigCert;

  /**
   * digest algorithm to use in the signature
   */
  private final String sigDigestAlg;

  /**
   * specifies whether to sign and whether to include the signature certificate
   */
  private final SigEntryType sigType;

  private EidasSigner(boolean includeCert, PrivateKey key, X509Certificate cert, String digestAlg)
  {
    if (key == null || cert == null || digestAlg == null)
    {
      throw new IllegalArgumentException("must specify all arguments when setting a signer");
    }
    sigType = includeCert ? XMLSignatureHandler.SigEntryType.CERTIFICATE
      : XMLSignatureHandler.SigEntryType.ISSUERSERIAL;
    sigKey = key;
    sigCert = cert;
    sigDigestAlg = digestAlg;
  }

  /**
   * Create a XMLSigner Object the sign algo will be http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1 if
   * using a cert if a RSA Key or http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256 if using a cert with a
   * EC key. The canonicalization algorithm is set to http://www.w3.org/2001/10/xml-exc-c14n# and the digest
   * algorithm to http://www.w3.org/2001/04/xmlenc#sha256
   *
   * @param includeCert
   * @param key
   * @param cert
   */
  public EidasSigner(boolean includeCert, PrivateKey key, X509Certificate cert)
  {
    this(includeCert, key, cert, DIGEST_DEFAULT);
  }

  EidasSigner(PrivateKey key, X509Certificate cert)
  {
    this(true, key, cert);
  }

  public EidasSigner(KeyStore keyStore)
    throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    this(true, (PrivateKey)keyStore.getKey(SAML_SIGNING, null),
         (X509Certificate)keyStore.getCertificate(SAML_SIGNING));
  }
}
