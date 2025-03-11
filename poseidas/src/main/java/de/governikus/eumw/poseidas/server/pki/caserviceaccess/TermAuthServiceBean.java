package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import org.springframework.stereotype.Service;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
@RequiredArgsConstructor
/**
 * This class is a wrapper for the {@link TermAuthService} to use the service as a bean.
 */

public class TermAuthServiceBean
{

  private final ConfigurationService configurationService;

  private final HSMServiceHolder hsmServiceHolder;


  /**
   * Gets the {@link TermAuthService} for an entity ID
   *
   * @param entityID the entity ID for which the {@link TermAuthService} should be created
   * @return the {@link TermAuthService} for the passed entity ID
   * @throws GovManagementException throws when the service can not be created
   */
  public TermAuthService getTermAuthService(String entityID) throws GovManagementException
  {
    ServiceProviderType serviceProviderType = getServiceProvider(entityID);
    DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProviderType);
    String serviceUrl = dvcaConfiguration.getTerminalAuthServiceUrl();
    X509Certificate dvcaCertificate = configurationService.getCertificate(dvcaConfiguration.getServerSSLCertificateName());

    try
    {
      PKIServiceConnector connector;
      KeyStore hsmKeyStore = hsmServiceHolder.getKeyStore();
      if (hsmKeyStore == null)
      {
        de.governikus.eumw.poseidas.server.idprovider.config.KeyPair clientKeyPair = configurationService.getKeyPair(serviceProviderType.getClientKeyPairName());
        List<X509Certificate> clientCertificate = List.of(clientKeyPair.getCertificate());
        connector = new PKIServiceConnector(600, dvcaCertificate, clientKeyPair.getKey(), clientCertificate,
                                            serviceProviderType.getCVCRefID());

      }
      else
      {
        connector = new PKIServiceConnector(600, dvcaCertificate, hsmKeyStore, null, serviceProviderType.getCVCRefID());
      }
      return new TermAuthService(connector, serviceUrl);
    }
    catch (GeneralSecurityException | IOException | NullPointerException e)
    {
      log.error("{}: problem with crypto data", serviceProviderType.getCVCRefID(), e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      log.error("{}: problem with crypto data", serviceProviderType.getCVCRefID(), e);
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  private ServiceProviderType getServiceProvider(String entityID) throws GovManagementException
  {
    return configurationService.getConfiguration()
                               .orElseThrow(() -> new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage()))
                               .getEidConfiguration()
                               .getServiceProvider()
                               .stream()
                               .filter(sp -> sp.getName().equals(entityID))
                               .findFirst()
                               .orElseThrow(() -> new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage()));
  }

}
