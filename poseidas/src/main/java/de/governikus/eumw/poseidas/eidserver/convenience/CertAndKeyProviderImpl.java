/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardserver.eac.ta.CertAndKeyProvider;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;



/**
 * Implementation of the CertAndKeyProvider from the card server package
 *
 * @author <a href="mail:obe@bos-bremen.de">Ole Behrens</a>
 */
public class CertAndKeyProviderImpl implements CertAndKeyProvider
{

  private static final Log LOG = LogFactory.getLog(CertAndKeyProviderImpl.class.getName());

  private static final String LOG_PREFIX = "[Certificates and Keys]";

  private final Map<String, ECCVCertificate> certMap = new HashMap<>();

  private final Map<String, byte[]> keyMap = new HashMap<>();


  /**
   * add an terminal CVC into the provider that also contains a private key. This is package private on purpose.
   *
   * @param certBuffer the bytes of the certificate.
   * @throws IOException if the bytes do not represent a proper certificate
   */
  public void addTerminalCVC(TerminalData cvc) throws IOException
  {
    byte[] encoded = cvc.getEncoded();
    addCert(encoded);
    ECCVCertificate cert = new ECCVCertificate(encoded);
    String holderName = new String(cert.getCVCPart(ECCVCPath.HOLDER_REFERENCE).getValue(), StandardCharsets.UTF_8);
    if (this.keyMap.containsKey(holderName))
    {
      LOG.debug(LOG_PREFIX + "Terminal key already set for holder name: " + holderName);
    }
    else
    {
      this.keyMap.put(holderName, cvc.getPrivateKey());
    }
  }

  /**
   * add an issuer CVC into the provider, so it can build a certificate chain. This is package private on purpose.
   *
   * @param certBuffer the bytes of the certificate.
   * @throws IOException if the bytes do not represent a proper certificate
   */
  public void addCert(byte[] certBuffer) throws IOException
  {
    ECCVCertificate cert = new ECCVCertificate(certBuffer);
    String holderName = new String(cert.getCVCPart(ECCVCPath.HOLDER_REFERENCE).getValue());
    if (this.certMap.containsKey(holderName))
    {
      LOG.debug(LOG_PREFIX + "Terminal or DV certificate already set for holder name: " + holderName);
    }
    else
    {
      LOG.debug(LOG_PREFIX + "Terminal or DV certificate added to provider: " + holderName);
      this.certMap.put(holderName, cert);
    }
  }

  @Override
  public List<byte[]> getCertChain(String rootHolder, String termHolder) throws IOException
  {
    List<byte[]> result = new ArrayList<>();
    if (rootHolder == null || rootHolder.length() == 0 || termHolder == null || termHolder.length() == 0)
    {
      throw new IllegalArgumentException("Null or empty string not permitted for holder values");
    }

    LOG.debug(LOG_PREFIX + "Find root '" + rootHolder + "' for term holder '" + termHolder + "'");

    String nextTermHolder = termHolder;
    // Get first term holder
    do
    {
      // Get certificate from map
      ECCVCertificate cert = this.certMap.get(nextTermHolder);
      if (cert == null)
      {
        LOG.debug(LOG_PREFIX + "term holder not available: " + nextTermHolder);
        return null;
      }

      // Get issuer from this certificate
      String issuer = new String(cert.getCVCPart(ECCVCPath.CA_REFERENCE).getValue(), StandardCharsets.UTF_8);
      LOG.debug(LOG_PREFIX + "Issuer to check: " + issuer);

      // If issuer is the term holder check if this holder fits the root holder
      if (issuer.equals(nextTermHolder))
      {
        if (issuer.equals(rootHolder))
        {
          // Issuer is the searched root holder. Do not add the root certificate
          return result;
        }
        else
        {
          // Issuer do not fit searched root holder
          LOG.info(LOG_PREFIX + termHolder + " with " + issuer + " not in chain with root: " + rootHolder);
          return null;
        }
      }
      else
      {
        result.add(0, cert.getEncoded());
        if (issuer.equals(rootHolder))
        {
          // Add this certificate. Do not need the term holder certificate
          return result;
        }
        else
        {
          // Set next certificate to check
          nextTermHolder = issuer;
        }
      }
    }
    while (true);
  }

  @Override
  public byte[] getKeyByHolder(String holder)
  {
    LOG.debug(LOG_PREFIX + " I:" + holder);
    return keyMap.get(holder);
  }

}
