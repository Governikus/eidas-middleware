/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.poseidas.server.common.BerCaPolicyConstants;


/**
 * This is a wrapper for the {@link EPAConnectorConfigurationType} JaxB configuration object.
 *
 * @author hme
 */
public class PkiConnectorConfigurationDto extends AbstractConfigDto<PkiConnectorConfigurationType>
{

  private static final Log LOG = LogFactory.getLog(PkiConnectorConfigurationDto.class);

  private X509Certificate blackListTrustAnchor, masterListTrustAnchor, defectListTrustAnchor;

  private Map<String, SslKeysDto> sslKeys;

  /**
   * Create new instance filled with data from given JAXB object
   *
   * @param jaxBConfig
   */
  PkiConnectorConfigurationDto(PkiConnectorConfigurationType jaxBConfig)
  {
    super(jaxBConfig);
  }

  @Override
  protected void setJaxbConfig(PkiConnectorConfigurationType jaxBConfig)
  {
    this.jaxbConfig = jaxBConfig;
    blackListTrustAnchor = getCert(jaxbConfig.getBlackListTrustAnchor());
    masterListTrustAnchor = getCert(jaxbConfig.getMasterListTrustAnchor());
    defectListTrustAnchor = getCert(jaxbConfig.getDefectListTrustAnchor());
    if (jaxbConfig.getPolicyImplementationId() == null)
    {
      jaxbConfig.setPolicyImplementationId(BerCaPolicyConstants.POLICY_SIGNTRUST_A);
    }
    if (jaxbConfig.getSslKeys().isEmpty())
    {
      SslKeysType defaultKeys = new SslKeysType();
      defaultKeys.setId("default");
      jaxbConfig.getSslKeys().add(defaultKeys);
    }
    sslKeys = new TreeMap<>();
    for ( SslKeysType sslKeyEntry : jaxbConfig.getSslKeys() )
    {
      sslKeys.put(sslKeyEntry.getId(), new SslKeysDto(sslKeyEntry));
    }
    String sslKeysId = null;
    if (jaxbConfig.getSslKeys().size() == 1)
    {
      sslKeysId = jaxbConfig.getSslKeys().get(0).getId();
    }
    if (jaxbConfig.getTerminalAuthService() == null)
    {
      jaxbConfig.setTerminalAuthService(new PkiServiceType());
      jaxbConfig.getTerminalAuthService().setSslKeysId(sslKeysId);
    }
    if (jaxbConfig.getRestrictedIdService() == null)
    {
      jaxbConfig.setRestrictedIdService(new PkiServiceType());
      jaxbConfig.getRestrictedIdService().setSslKeysId(sslKeysId);
    }
    if (jaxbConfig.getPassiveAuthService() == null)
    {
      jaxbConfig.setPassiveAuthService(new PkiServiceType());
      jaxbConfig.getPassiveAuthService().setSslKeysId(sslKeysId);
    }
    if (jaxbConfig.getDvcaCertDescriptionService() == null)
    {
      jaxbConfig.setDvcaCertDescriptionService(new PkiServiceType());
      jaxbConfig.getDvcaCertDescriptionService().setSslKeysId(sslKeysId);
    }
  }

  private X509Certificate getCert(byte[] data)
  {
    try
    {
      if (data != null)
      {
        return Utils.readCert(data);
      }
    }
    catch (CertificateException e)
    {
      LOG.error("illegal trusted anchor certificate", e);
    }
    return null;
  }

  /**
   * Return the wrapped (and updated) object.
   */
  @Override
  public PkiConnectorConfigurationType getJaxbConfig()
  {
    jaxbConfig.getSslKeys().clear();
    for ( SslKeysDto sslDto : sslKeys.values() )
    {
      jaxbConfig.getSslKeys().add(sslDto.getJaxbConfig());
    }
    return jaxbConfig;
  }

  /**
   * Return the list of defined SSL key sets
   */
  public Map<String, SslKeysDto> getSslKeys()
  {
    return sslKeys;
  }

  /**
   * Return the service connection for terminal auth - service which provides CVCs
   */
  public PkiServiceType getTerminalAuthService()
  {
    return jaxbConfig.getTerminalAuthService();
  }

  /**
   * Return the service connection for restricted ID - service which provides public sector key and blacklist
   */
  public PkiServiceType getRestrictedIdService()
  {
    return jaxbConfig.getRestrictedIdService();
  }

  /**
   * Return the service connection for passive authentication - service which provides master and defect list.
   * These list are down-loaded separately for each client. It is not specified what to do when these lists
   * differ.
   */
  public PkiServiceType getPassiveAuthService()
  {
    return jaxbConfig.getPassiveAuthService();
  }

  public PkiServiceType getDvcaCertDescriptionService()
  {
    return jaxbConfig.getDvcaCertDescriptionService();
  }

  /**
   * @see #getDefectListTrustAnchor()
   */
  public void setDefectListTrustAnchor(X509Certificate defectListTrustAnchor) throws CertificateException
  {
    this.defectListTrustAnchor = defectListTrustAnchor;
    jaxbConfig.setDefectListTrustAnchor(defectListTrustAnchor == null ? null
      : defectListTrustAnchor.getEncoded());

  }

  /**
   * Return signer certificate or signers issuer certificate for checking signature of defect list.
   */
  public X509Certificate getDefectListTrustAnchor()
  {
    return defectListTrustAnchor;
  }

  /**
   * @see #getBlackListTrustAnchor()
   */
  public void setBlackListTrustAnchor(X509Certificate blackListTrustAnchor) throws CertificateException
  {
    this.blackListTrustAnchor = blackListTrustAnchor;
    jaxbConfig.setBlackListTrustAnchor(blackListTrustAnchor == null ? null
      : blackListTrustAnchor.getEncoded());
  }

  /**
   * Return signer certificate or signers issuer certificate for checking signature of black list.
   */
  public X509Certificate getBlackListTrustAnchor()
  {
    return blackListTrustAnchor;
  }

  /**
   * @see #getMasterListTrustAnchor()
   */
  public void setMasterListTrustAnchor(X509Certificate masterListTrustAnchor) throws CertificateException
  {
    this.masterListTrustAnchor = masterListTrustAnchor;
    jaxbConfig.setMasterListTrustAnchor(masterListTrustAnchor == null ? null
      : masterListTrustAnchor.getEncoded());
  }

  /**
   * Return signer certificate or signers issuer certificate for checking signature of master list.
   */
  public X509Certificate getMasterListTrustAnchor()
  {
    return masterListTrustAnchor;
  }

  /**
   * @see #getAutentURL()
   */
  public void setAutentURL(String autentURL)
  {
    jaxbConfig.setAutentServerUrl(autentURL);
  }

  /**
   * Return the URL of the poseidas server connector to be used by the BerCA - need an own connector in case the
   * BerCA does not implement configurable trust anchors for SSL.
   */
  public String getAutentURL()
  {
    return jaxbConfig.getAutentServerUrl();
  }

  /**
   * Return ID of a policy object which describes the handling of the BerCA
   */
  public String getBerCaPolicyId()
  {
    return jaxbConfig.getPolicyImplementationId();
  }

  /**
   * see constant definitions for allowed values
   */
  public void setBerCaPolicyId(String id)
  {
    jaxbConfig.setPolicyImplementationId(id);
  }

  /**
   * Set several attributes which are probably shared between service providers as set in the given object.
   *
   * @param other
   */
  public void setDefaultValues(PkiConnectorConfigurationDto other)
  {
    setAutentURL(other.getAutentURL());
    setBerCaPolicyId(other.getBerCaPolicyId());
    try
    {
      setBlackListTrustAnchor(other.getBlackListTrustAnchor());
      setMasterListTrustAnchor(other.getMasterListTrustAnchor());
      setDefectListTrustAnchor(other.getDefectListTrustAnchor());
    }
    catch (CertificateException e)
    {
      LOG.error("cannot handle certificate");
    }
    getRestrictedIdService().setUrl(other.getRestrictedIdService().getUrl());
    getTerminalAuthService().setUrl(other.getTerminalAuthService().getUrl());
    getPassiveAuthService().setUrl(other.getPassiveAuthService().getUrl());
    getDvcaCertDescriptionService().setUrl(other.getDvcaCertDescriptionService().getUrl());
    getSslKeys().clear();
    for ( Entry<String, SslKeysDto> otherKey : other.getSslKeys().entrySet() )
    {
      SslKeysDto mySslKeyDto = new SslKeysDto(otherKey.getKey());
      try
      {
        mySslKeyDto.setServerCertificate(otherKey.getValue().getServerCertificate());
        List<X509Certificate> chain = otherKey.getValue().getClientCertificateChain();
        mySslKeyDto.setClientKeyAndCert(otherKey.getValue().getClientKey(),
                                        chain.toArray(new Certificate[chain.size()]));
      }
      catch (CertificateException e)
      {
        LOG.error("cannot handle certificate");
      }
    }
  }
}
