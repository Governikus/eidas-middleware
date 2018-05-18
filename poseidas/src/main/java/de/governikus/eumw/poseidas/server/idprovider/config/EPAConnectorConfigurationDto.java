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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;


/**
 * This is a wrapper for the {@link EPAConnectorConfigurationType} JaxB configuration object.
 * 
 * @author hme
 */
public class EPAConnectorConfigurationDto extends AbstractConfigDto<EPAConnectorConfigurationType>
{

  private static final Log LOG = LogFactory.getLog(EPAConnectorConfigurationDto.class);

  private X509Certificate clientsSslCert, clientsSslCert2;

  private PkiConnectorConfigurationDto pkiConnectorConfiguration;

  /**
   * Create new instance filled with data from given JAXB object
   * 
   * @param jaxBConfig
   */
  EPAConnectorConfigurationDto(EPAConnectorConfigurationType jaxBConfig, ServiceProviderDto sp)
  {
    super(jaxBConfig);
    if (jaxBConfig.isUpdateCVC() == null && sp != null)
    {
      jaxBConfig.setUpdateCVC(jaxbConfig.getCVCRefID().equals(sp.getEntityID()));
    }
  }

  @Override
  protected void setJaxbConfig(EPAConnectorConfigurationType jaxBConfig)
  {
    this.jaxbConfig = jaxBConfig;

    try
    {
      clientsSslCert = Utils.readCert(jaxbConfig.getClientSSLCert());
      clientsSslCert2 = Utils.readCert(jaxbConfig.getClientSSLCert2());
    }
    catch (CertificateException e)
    {
      LOG.error("illegal ssl certificate");
    }

    PkiConnectorConfigurationType jaxbPkiConf = jaxbConfig.getPkiConnectorConfiguration();
    if (jaxbPkiConf == null)
    {
      jaxbPkiConf = new PkiConnectorConfigurationType();
    }
    pkiConnectorConfiguration = new PkiConnectorConfigurationDto(jaxbPkiConf);

    if (jaxbConfig.getCVCRefID() == null)
    {
      jaxbConfig.setCVCRefID(UUID.randomUUID().toString());
      jaxbConfig.setUpdateCVC(Boolean.TRUE);
    }
  }

  /**
   * Return the wrapped (and updated) object.
   */
  @Override
  public EPAConnectorConfigurationType getJaxbConfig()
  {
    jaxbConfig.setPkiConnectorConfiguration(pkiConnectorConfiguration == null ? null
      : pkiConnectorConfiguration.getJaxbConfig());
    return jaxbConfig;
  }

  /**
   * Set the ID of the terminal permission certificate data record.
   */
  public void setCVCRefID(String refID)
  {
    jaxbConfig.setCVCRefID(refID);
  }

  /**
   * Return the reference to the CVC data in the local database
   */
  public String getCVCRefID()
  {
    return jaxbConfig.getCVCRefID();
  }

  public boolean isUpdateCVC()
  {
    return !Boolean.FALSE.equals(jaxbConfig.isUpdateCVC());
  }

  public void setUpdateCVC(boolean updateCVC)
  {
    jaxbConfig.setUpdateCVC(updateCVC);
  }

  /**
   * Return the SSL certificate of the client needed for accessing the eID service
   */
  public X509Certificate getClientSSLCert()
  {
    return clientsSslCert;
  }

  /**
   * @see #getClientSSLCert()
   */
  public void setClientSSLCert(X509Certificate value) throws CertificateException
  {
    clientsSslCert = value;
    jaxbConfig.setClientSSLCert(value == null ? null : value.getEncoded());
  }

  /**
   * Return the second SSL certificate of the client needed for accessing the eID service
   */
  public X509Certificate getClientSSLCert2()
  {
    return clientsSslCert2;
  }

  /**
   * @see #getClientSSLCert2()
   */
  public void setClientSSLCert2(X509Certificate value) throws CertificateException
  {
    clientsSslCert2 = value;
    jaxbConfig.setClientSSLCert2(value == null ? null : value.getEncoded());
  }

  /**
   * Return the URL where the client should direct its PAOS communication to.
   */
  public String getPaosReceiverURL()
  {
    return jaxbConfig.getPaosReceiverURL();
  }

  /**
   * @see #getPaosReceiverURL()
   */
  public void setPaosReceiverURL(String value)
  {
    jaxbConfig.setPaosReceiverURL(value);
  }

  /**
   * Return the URL where the client should redirect to in case of communication error.
   */
  public String getCommunicationErrorURL()
  {
    return jaxbConfig.getCommunicationErrorURL();
  }

  /**
   * @see #setCommunicationErrorURL(String)
   */
  public void setCommunicationErrorURL(String value)
  {
    jaxbConfig.setCommunicationErrorURL(value);
  }

  /**
   * Returns the number of hours the CVC should be refreshed before it expires. If not value is set it will
   * return 12 hours.
   */
  public int getHoursRefreshCVCBeforeExpires()
  {
    if (jaxbConfig.getHoursRefreshCVCBeforeExpires() == null)
    {
      return 20;
    }
    return jaxbConfig.getHoursRefreshCVCBeforeExpires().intValue();
  }

  /**
   * @see #getHoursRefreshCVCBeforeExpires()
   */
  public void setHoursRefreshCVCBeforeExpires(int value)
  {
    jaxbConfig.setHoursRefreshCVCBeforeExpires(Integer.valueOf(value));
  }

  /**
   * return the configuration for connecting to the PKI services
   */
  public PkiConnectorConfigurationDto getPkiConnectorConfiguration()
  {
    return pkiConnectorConfiguration;
  }

  /**
   * @see #getPkiConnectorConfiguration()
   */
  public void setPkiConnectorConfiguration(PkiConnectorConfigurationDto pkiConnectorConfiguration)
  {
    this.pkiConnectorConfiguration = pkiConnectorConfiguration;
  }

  /**
   * Set several attributes which are probably shared between service providers as set in the given object.
   * 
   * @param other
   */
  public void setDefaultValues(EPAConnectorConfigurationDto other)
  {
    setHoursRefreshCVCBeforeExpires(other.getHoursRefreshCVCBeforeExpires());
    setPaosReceiverURL(other.getPaosReceiverURL());
    setCommunicationErrorURL(other.getCommunicationErrorURL());
    if (other.getPkiConnectorConfiguration() != null)
    {
      setPkiConnectorConfiguration(new PkiConnectorConfigurationDto(new PkiConnectorConfigurationType()));
      getPkiConnectorConfiguration().setDefaultValues(other.getPkiConnectorConfiguration());
    }
  }

}
