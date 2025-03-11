package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This factory combines the creation of services that communicate with the DVCA.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DvcaServiceFactory
{

  private final ConfigurationService configurationService;

  @Value("${poseidas.ri-service.1-40:false}")
  private boolean useRiService140;

  /**
   * Creates a PassiveAuthService service.
   *
   * @param serviceProvider
   * @param hsmKeyStore
   * @return PassiveAuthService or exception is thrown
   * @throws GovManagementException
   */
  public PassiveAuthService passiveAuthService(ServiceProviderType serviceProvider, KeyStore hsmKeyStore)
    throws GovManagementException
  {
    try
    {
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProvider);
      PKIServiceConnector connector = getPkiServiceConnector(serviceProvider, hsmKeyStore, dvcaConfiguration, 60);
      String serviceUrl = dvcaConfiguration.getPassiveAuthServiceUrl();
      return new PassiveAuthService(connector, serviceUrl);
    }
    catch (GeneralSecurityException | IOException | NullPointerException e)
    {
      log.error("{}: problem with crypto data of SP", serviceProvider.getCVCRefID(), e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  /**
   * Creates a TermAuthService service.
   *
   * @param serviceProvider
   * @param hsmKeyStore
   * @return TermAuthService or exception is thrown
   * @throws GovManagementException
   */
  public TermAuthService createTermAuthService(ServiceProviderType serviceProvider, KeyStore hsmKeyStore)
    throws GovManagementException
  {
    try
    {
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProvider);
      PKIServiceConnector connector = getPkiServiceConnector(serviceProvider, hsmKeyStore, dvcaConfiguration, 600);
      String serviceUrl = dvcaConfiguration.getTerminalAuthServiceUrl();
      return new TermAuthService(connector, serviceUrl);
    }
    catch (GeneralSecurityException | IOException | NullPointerException e)
    {
      log.error("{}: problem with crypto data", serviceProvider.getCVCRefID(), e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      log.error("{}: problem with crypto data", serviceProvider.getCVCRefID(), e);
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }


  /**
   * Creates a RestrictedIdService service.
   *
   * @param serviceProvider
   * @param hsmKeyStore
   * @return RestrictedIdService or exception is thrown
   * @throws GovManagementException
   */
  public RestrictedIdService createRestrictedIdService(ServiceProviderType serviceProvider, KeyStore hsmKeyStore)
    throws GovManagementException
  {
    try
    {
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProvider);
      PKIServiceConnector connector = getPkiServiceConnector(serviceProvider, hsmKeyStore, dvcaConfiguration, 180);
      String serviceUrl = dvcaConfiguration.getRestrictedIdServiceUrl();
      if (useRiService140)
      {
        return new RestrictedIdService140(connector, serviceUrl);
      }
      return new RestrictedIdService110(connector, serviceUrl);
    }
    catch (GeneralSecurityException | IOException | NullPointerException e)
    {
      log.error("{}: problem with crypto data of this SP", serviceProvider.getCVCRefID(), e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  public PKIServiceConnector getPkiServiceConnector(ServiceProviderType serviceProvider,
                                                    KeyStore hsmKeyStore,
                                                    DvcaConfigurationType dvcaConfiguration,
                                                    int timeout)
    throws GeneralSecurityException
  {
    X509Certificate dvcaCertificate = configurationService.getCertificate(dvcaConfiguration.getServerSSLCertificateName());

    String cvcRefId = serviceProvider.getCVCRefID();
    PKIServiceConnector connector;
    if (hsmKeyStore == null)
    {
      KeyPair clientKeyPair = configurationService.getKeyPair(serviceProvider.getClientKeyPairName());
      List<X509Certificate> clientCertificate = List.of(clientKeyPair.getCertificate());
      connector = new PKIServiceConnector(timeout, dvcaCertificate, clientKeyPair.getKey(), clientCertificate,
                                          cvcRefId);
    }
    else
    {
      connector = new PKIServiceConnector(timeout, dvcaCertificate, hsmKeyStore, null, cvcRefId);
    }
    return connector;
  }
}
