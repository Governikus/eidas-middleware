/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.eidserver.crl.exception.CertificateValidationException;


/**
 * This class is a Simple implementation of CRL fetcher, which validates downloaded CRLs using HTTP downloads.
 */
public class HttpCrlFetcher implements CrlFetcher
{

  private final Set<X509Certificate> trustAnchors;

  /**
   * Constructor for {@link HttpCrlFetcher} that takes a set of {@link X509Certificate} to validate the
   * signature of a {@link X509CRL}.
   *
   * @param trustAnchors validates {@link X509CRL} signature
   */
  public HttpCrlFetcher(Set<X509Certificate> trustAnchors)
  {
    this.trustAnchors = trustAnchors;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public X509CRL get(String url) throws CertificateValidationException
  {
    return download(url);
  }

  protected X509CRL download(String url) throws CertificateValidationException
  {
    try
    {
      if (url != null && url.matches("http[s]{0,1}://.*"))
      {
        X509CRL crl = httpDownload(url);
        Optional<X509Certificate> signer = trustAnchors.stream()
                                                       .filter(CertificateUtil.findIssuerByAuthorityKeyIdentifier(crl.getExtensionValue(Extension.authorityKeyIdentifier.getId())))
                                                       .findAny();
        if (signer.isPresent())
        {
          crl.verify(signer.get().getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
          return crl;
        }
        else
        {
          throw new CertificateValidationException("Could not verify CRL");
        }
      }
    }
    catch (CRLException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
      | SignatureException e)
    {
      throw new CertificateValidationException("Could not verify CRL", e);
    }
    return null;
  }

  protected X509CRL httpDownload(String url) throws CertificateValidationException
  {
    try
    {
      CertificateFactory cf = CertificateFactory.getInstance("x509", BouncyCastleProvider.PROVIDER_NAME);
      return (X509CRL)cf.generateCRL(URI.create(url).toURL().openStream());
    }
    catch (IOException | CRLException | CertificateException | NoSuchProviderException e)
    {
      throw new CertificateValidationException(String.format("Failed to download CRL '%s' (%s)",
                                                             url,
                                                             e.getMessage()),
                                               e);
    }
  }
}
