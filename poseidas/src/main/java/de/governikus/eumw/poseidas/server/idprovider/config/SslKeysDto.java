/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

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

  /**
   * Create new empty instance
   *
   * @param id
   */
  SslKeysDto(String id)
  {
    super(new SslKeysType());
    jaxbConfig.setId(id);
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
        clientCertificateChain.add(Utils.readCert(clientCert));
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
   * Set the ID of the terminal permission certificate data record.
   */
  public void setId(String id)
  {
    jaxbConfig.setId(id);
  }

  /**
   * Return the reference to the CVC data in the local database
   */
  public String getId()
  {
    return jaxbConfig.getId();
  }

  /**
   * Return the SSL certificate of the client needed for accessing a PKI service
   */
  public X509Certificate getClientCertificate()
  {
    if (clientCertificateChain.isEmpty())
    {
      return null;
    }
    return clientCertificateChain.get(0);
  }

  /**
   * Returns the SSL certificate chain of the client needed for accessing a PKI service
   */
  public List<X509Certificate> getClientCertificateChain()
  {
    return clientCertificateChain;
  }

  /**
   * Return the SSL certificate of the PKI server
   */
  public X509Certificate getServerCertificate()
  {
    return serverCertificate;
  }

  /**
   * @see #getClientCertificate()
   */
  public void setServerCertificate(X509Certificate value) throws CertificateException
  {
    serverCertificate = value;
    jaxbConfig.setServerCertificate(value == null ? null : value.getEncoded());
  }

  /**
   * return the private key for SSL communication with the PKI service
   */
  public PrivateKey getClientKey()
  {
    return clientKey;
  }

  public X509KeyPair getClientKeyPair()
  {
    return new X509KeyPair(clientKey,
                           clientCertificateChain.toArray(new X509Certificate[clientCertificateChain.size()]));
  }

  /**
   * @see #getClientCertificate()
   * @see #getClientKey()
   */
  void setClientKeyAndCert(PrivateKey key, Certificate[] certChain) throws CertificateEncodingException
  {
    clientCertificateChain.clear();
    jaxbConfig.getClientCertificate().clear();
    for ( Certificate cert : certChain )
    {
      if (cert != null)
      {
        clientCertificateChain.add((X509Certificate)cert);
        jaxbConfig.getClientCertificate().add(cert.getEncoded());
      }
    }
    clientKey = key;
    jaxbConfig.setClientKey(key == null ? null : key.getEncoded());
  }
}
