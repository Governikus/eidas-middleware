/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.Reader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.Extension;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.config.schema.CoreConfigurationType;
import de.governikus.eumw.poseidas.config.schema.ObjectFactory;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;


/**
 * Wrapper for CoreConfigurationType to make generic MBean look better.
 * 
 * @author tt
 */
public class CoreConfigurationDto extends AbstractConfigDto<CoreConfigurationType>
{

  private static final Log LOG = LogFactory.getLog(CoreConfigurationDto.class);

  private PrivateKey signatureKeyWebService;

  private X509Certificate signatureCertWebService;

  private Map<String, ServiceProviderDto> serviceProviders;

  private static Pattern emailReplacePattern = Pattern.compile("(,|, |^)E=");

  /**
   * For creation you need an object to wrap.
   * 
   * @param jaxBConfig
   */
  CoreConfigurationDto(CoreConfigurationType jaxBConfig)
  {
    super(jaxBConfig);
  }

  @Override
  protected void setJaxbConfig(CoreConfigurationType jaxBConfig)
  {
    this.jaxbConfig = jaxBConfig;
    try
    {
      if (jaxbConfig.getSignatureCertWebService() != null)
      {
        signatureCertWebService = Utils.readCert(jaxbConfig.getSignatureCertWebService());
      }
      if (jaxbConfig.getSignatureKeyWebService() != null)
      {
        signatureKeyWebService = KeyFactory.getInstance(signatureCertWebService.getPublicKey().getAlgorithm())
                                           .generatePrivate(new PKCS8EncodedKeySpec(jaxbConfig.getSignatureKeyWebService()));
      }
      serviceProviders = new TreeMap<>();
      for ( ServiceProviderType provider : jaxbConfig.getServiceProvider() )
      {
        serviceProviders.put(provider.getEntityID(), new ServiceProviderDto(provider));
      }
      if (jaxbConfig.getTimerConfiguration() == null)
      {
        TimerConfigurationType timerConf = new TimerConfigurationType();
        jaxbConfig.setTimerConfiguration(timerConf);
      }

      TimerConfigurationType timerConf = jaxbConfig.getTimerConfiguration();
      if (timerConf.getBlacklistRenewal() == null)
      {
        timerConf.setBlacklistRenewal(new TimerType());
        timerConf.getBlacklistRenewal().setLength(15);
        timerConf.getBlacklistRenewal().setUnit(Calendar.MINUTE);
      }
      if (timerConf.getCertRenewal() == null)
      {
        timerConf.setCertRenewal(new TimerType());
        timerConf.getCertRenewal().setLength(1);
        timerConf.getCertRenewal().setUnit(Calendar.HOUR_OF_DAY);
      }
      if (timerConf.getMasterAndDefectListRenewal() == null)
      {
        timerConf.setMasterAndDefectListRenewal(new TimerType());
        timerConf.getMasterAndDefectListRenewal().setLength(1);
        timerConf.getMasterAndDefectListRenewal().setUnit(Calendar.DAY_OF_MONTH);
      }

      if (jaxbConfig.getSessionMaxPendingRequests() == 0)
      {
        jaxbConfig.setSessionMaxPendingRequests(500);
      }
    }
    catch (GeneralSecurityException e)
    {
      LOG.error("can not load key or certificate from core configuration xml.", e);
    }
  }

  /**
   * Create new object from XML data
   * 
   * @param reader
   * @throws JAXBException
   */
  @SuppressWarnings("unchecked")
  static CoreConfigurationDto readFrom(Reader reader) throws JAXBException
  {
    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
    Object po = context.createUnmarshaller().unmarshal(reader);
    CoreConfigurationType parsed = null;
    if (po instanceof CoreConfigurationType)
    {
      parsed = (CoreConfigurationType)po;
    }
    else
    {
      parsed = ((JAXBElement<CoreConfigurationType>)po).getValue();
    }
    return new CoreConfigurationDto(parsed);
  }

  @Override
  public CoreConfigurationType getJaxbConfig()
  {
    jaxbConfig.getServiceProvider().clear();
    for ( ServiceProviderDto provider : serviceProviders.values() )
    {
      jaxbConfig.getServiceProvider().add(provider.getJaxbConfig());
    }
    return jaxbConfig;
  }

  /**
   * Return the URL of the SSO service. Note that the URL of the web service is different!
   */
  public String getServerUrl()
  {
    return jaxbConfig.getServerUrl();
  }

  /**
   * Set the URL of the SSO service.
   */
  public void setServerUrl(String serverUrl)
  {
    jaxbConfig.setServerUrl(serverUrl);
  }

  /**
   * Return the private key this service signs with.
   */
  public PrivateKey getSignatureKeyWebService()
  {
    return signatureKeyWebService;
  }

  /**
   * Return the signature certificate of the identity server.
   */
  public X509Certificate getSignatureCertWebService()
  {
    return signatureCertWebService;
  }

  /**
   * Return the set of serviceProviders addressed by entityID
   */
  public Map<String, ServiceProviderDto> getServiceProvider()
  {
    return serviceProviders;
  }

  /**
   * Return whether the session manager should store the sessions in database (alternative is memory).
   */
  public boolean isSessionManagerUsesDatabase()
  {
    return jaxbConfig.isSessionManagerUsesDatabase();
  }

  /**
   * Impose whether the session manager should store the sessions in database (alternative is memory).
   */
  public void setSessionManagerUsesDatabase(boolean value)
  {
    jaxbConfig.setSessionManagerUsesDatabase(value);
  }

  /**
   * Return the maximum number of sessions to be stored in the session store.
   */
  public int getSessionMaxPendingRequests()
  {
    return jaxbConfig.getSessionMaxPendingRequests();
  }

  /**
   * Set the maximum number of sessions to be stored in the session store.
   */
  public void setSessionMaxPendingRequests(int value)
  {
    jaxbConfig.setSessionMaxPendingRequests(value);
  }

  /**
   * Return the configuration for the renewal timer intervals.
   */
  public TimerConfigurationType getTimerConfiguration()
  {
    return jaxbConfig.getTimerConfiguration();
  }

  /**
   * Returns the service provider with the matching signature certificate.
   * 
   * @param clientsCert must match a configured certificate
   */
  public ServiceProviderDto findProviderForCertificate(X509Certificate clientsCert)
  {
    if (clientsCert == null)
    {
      return null;
    }
    // there may be providers which do not use the eID interface and therefore do not configure an SSL cert
    for ( ServiceProviderDto provider : getServiceProvider().values() )
    {
      if (provider.getEnabled() && provider.getEpaConnectorConfiguration() != null
          && (clientsCert.equals(provider.getSignatureCert())
              || clientsCert.equals(provider.getSignatureCert2())))
      {
        return provider;
      }
    }
    return null;
  }

  /**
   * Returns the nPA service provider with the matching ssl client certificate.
   * 
   * @param clientsCert must match a configured certificate
   */
  public ServiceProviderDto findProviderForSSLCertificate(X509Certificate clientsCert)
  {
    if (clientsCert == null)
    {
      return null;
    }

    for ( ServiceProviderDto provider : getServiceProvider().values() )
    {
      if (provider.getEnabled() && provider.getEpaConnectorConfiguration() != null
          && (clientsCert.equals(provider.getEpaConnectorConfiguration().getClientSSLCert())
              || clientsCert.equals(provider.getEpaConnectorConfiguration().getClientSSLCert2())))
      {
        return provider;
      }
    }
    return null;
  }

  /**
   * Return the service provider configuration using nPA validation and matching a given certificate. If no
   * configured SSL client certificate matches, this method looks for clients signature certificates instead.
   * Thus, the internal eID interface can address also such clients which have no SSL certificate configured.
   * 
   * @param issuer
   * @param serial
   */
  public ServiceProviderDto findProviderForCertificate(String issuer, BigInteger serial)
  {
    Matcher matcher = emailReplacePattern.matcher(issuer);
    X500Principal x500Issuer = new X500Principal(matcher.replaceAll("$1EMAILADDRESS="));
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null && cert.getSerialNumber().equals(serial)
          && (x500Issuer.equals(cert.getIssuerX500Principal())
              || issuer.equals(cert.getIssuerDN().getName())))
      {
        return providerConf;
      }
      cert = providerConf.getSignatureCert2();
      if (cert != null && cert.getSerialNumber().equals(serial)
          && (x500Issuer.equals(cert.getIssuerX500Principal())
              || issuer.equals(cert.getIssuerDN().getName())))
      {
        return providerConf;
      }
    }
    return null;
  }

  /**
   * Returns <code>true</code> if a service provider which has a signature certificate specified by issuer and
   * serial is found and uses that as first signature certificate, returns <code>false</code> if a service
   * provider which has a signature certificate specified by issuer and serial is found and uses that as
   * second signature certificate, returns <code>null</code> if no service provider found.
   * 
   * @param issuer
   * @param serial
   */
  public Boolean usesFirstCertForCertificate(String issuer, BigInteger serial)
  {
    Matcher matcher = emailReplacePattern.matcher(issuer);
    X500Principal x500Issuer = new X500Principal(matcher.replaceAll("$1EMAILADDRESS="));
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null && cert.getSerialNumber().equals(serial)
          && (x500Issuer.equals(cert.getIssuerX500Principal())
              || issuer.equals(cert.getIssuerDN().getName())))
      {
        return true;
      }
      cert = providerConf.getSignatureCert2();
      if (cert != null && cert.getSerialNumber().equals(serial)
          && (x500Issuer.equals(cert.getIssuerX500Principal())
              || issuer.equals(cert.getIssuerDN().getName())))
      {
        return false;
      }
    }
    return null;
  }

  /**
   * Return the service provider configuration using nPA validation and matching a given public key. If no
   * configured SSL client certificate matches, this method looks for clients signature certificates instead.
   * Thus, the internal eID interface can address also such clients which have no SSL certificate configured.
   * 
   * @param issuer
   * @param serial
   */
  public ServiceProviderDto findProviderForPublicKey(PublicKey pubKey)
  {
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null && cert.getPublicKey().equals(pubKey))
      {
        return providerConf;
      }

      cert = providerConf.getSignatureCert2();
      if (cert != null && cert.getPublicKey().equals(pubKey))
      {
        return providerConf;
      }
    }
    return null;
  }

  /**
   * Returns <code>true</code> if a service provider matching a given public key is found and uses that key as
   * first signature key, returns <code>false</code> if a service provider matching a given public key is
   * found and uses that key as second signature key, returns <code>null</code> if no service provider found.
   * 
   * @param pubKey
   */
  public Boolean usesFirstCertForPublicKey(PublicKey pubKey)
  {
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null && cert.getPublicKey().equals(pubKey))
      {
        return true;
      }

      cert = providerConf.getSignatureCert2();
      if (cert != null && cert.getPublicKey().equals(pubKey))
      {
        return false;
      }
    }
    return null;
  }

  /**
   * Return the security provider which has a signature certificate specified by subject key identifier.
   * 
   * @param identifier must match either the subject key identifier or be the whole certificate.
   */
  public ServiceProviderDto findProviderForCertificate(byte[] identifier)
  {
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null)
      {
        byte[] id = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        try
        {
          if (Arrays.equals(cert.getEncoded(), identifier) || (id != null && Arrays.equals(identifier, id)))
          {
            return providerConf;
          }
        }
        catch (CertificateEncodingException e)
        {
          LOG.error("cannot happen because cert has been parsed in same JVM", e);
        }
      }
      cert = providerConf.getSignatureCert2();
      if (cert != null)
      {
        byte[] id = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        try
        {
          if (Arrays.equals(cert.getEncoded(), identifier) || (id != null && Arrays.equals(identifier, id)))
          {
            return providerConf;
          }
        }
        catch (CertificateEncodingException e)
        {
          LOG.error("cannot happen because cert has been parsed in same JVM", e);
        }
      }
    }
    return null;
  }

  /**
   * Returns <code>true</code> if a service provider which has a signature certificate specified by subject
   * key identifier is found and uses that as first signature certificate, returns <code>false</code> if a
   * service provider which has a signature certificate specified by subject key identifier is found and uses
   * that as second signature certificate, returns <code>null</code> if no service provider found.
   * 
   * @param identifier must match either the subject key identifier or be the whole certificate.
   */
  public Boolean usesFirstCertForCertificate(byte[] identifier)
  {
    for ( ServiceProviderDto providerConf : getServiceProvider().values() )
    {
      X509Certificate cert = providerConf.getSignatureCert();
      if (cert != null)
      {

        byte[] id = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        try
        {
          if (Arrays.equals(cert.getEncoded(), identifier) || (id != null && Arrays.equals(identifier, id)))
          {
            return true;
          }
        }
        catch (CertificateEncodingException e)
        {
          LOG.error("cannot happen because cert has been parsed in same JVM", e);
        }
      }
      cert = providerConf.getSignatureCert2();
      if (cert != null)
      {
        byte[] id = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        try
        {
          if (Arrays.equals(cert.getEncoded(), identifier) || (id != null && Arrays.equals(identifier, id)))
          {
            return false;
          }
        }
        catch (CertificateEncodingException e)
        {
          LOG.error("cannot happen because cert has been parsed in same JVM", e);
        }
      }
    }
    return null;
  }

  public int getCertificateWarningMargin()
  {
    return jaxbConfig.getCertificateWarningMargin();
  }

  public void setCertificateWarningMargin(int cwm)
  {
    jaxbConfig.setCertificateWarningMargin(cwm);
  }
}
