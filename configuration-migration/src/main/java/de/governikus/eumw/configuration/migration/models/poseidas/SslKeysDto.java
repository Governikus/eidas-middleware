/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.poseidas;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;


/**
 * This is a wrapper for the {@link SslKeysType} JaxB configuration object.
 *
 * @author tt
 */
public class SslKeysDto extends AbstractConfigDto<SslKeysType>
{

  private static final Log LOG = LogFactory.getLog(SslKeysDto.class);

  private X509Certificate serverCertificate;

  private List<X509Certificate> clientCertificateChain;

  private PrivateKey clientKey;

  /**
   * Create new instance filled with data from given JAXB object
   *
   * @param jaxBConfig
   */
  SslKeysDto(SslKeysType jaxBConfig)
  {
    super(jaxBConfig);
  }

  @Override
  protected void setJaxbConfig(SslKeysType jaxBConfig)
  {
    this.jaxbConfig = jaxBConfig;
    clientCertificateChain = new ArrayList<>();
    try
    {
      serverCertificate = Utils.readCert(jaxbConfig.getServerCertificate());
      for ( byte[] clientCert : jaxbConfig.getClientCertificate() )
      {
        if (ArrayUtils.isNotEmpty(clientCert))
        {
          clientCertificateChain.add(Utils.readCert(clientCert));
        }
      }

      if (jaxbConfig.getClientKey() != null && !clientCertificateChain.isEmpty())
      {
        clientKey = KeyFactory.getInstance(clientCertificateChain.get(0).getPublicKey().getAlgorithm())
                              .generatePrivate(new PKCS8EncodedKeySpec(jaxbConfig.getClientKey()));
      }
    }
    catch (GeneralSecurityException e)
    {
      LOG.error("illegal ssl certificate");
    }
  }

  /**
   * Return the wrapped (and updated) object.
   */
  @Override
  public SslKeysType getJaxbConfig()
  {
    return jaxbConfig;
  }

  /**
   * Return the reference to the CVC data in the local database
   */
  public String getId()
  {
    return jaxbConfig.getId();
  }


  /**
   * Return the SSL certificate of the PKI server
   */
  public X509Certificate getServerCertificate()
  {
    return serverCertificate;
  }

  public void setServerCertificate(X509Certificate value) throws CertificateException
  {
    serverCertificate = value;
    jaxbConfig.setServerCertificate(value == null ? null : value.getEncoded());
  }

  public X509KeyPair getClientKeyPair()
  {
    return new X509KeyPair(clientKey, clientCertificateChain.toArray(new X509Certificate[0]));
  }
}
