package de.governikus.eumw.poseidas.service;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Service
@Slf4j
@RequiredArgsConstructor
public class ConfigKeyDataService
{

  private final ConfigurationService configurationService;

  /**
   * Check if a keypair is referenced in the configuration
   * 
   * @param keyPairName name of the keypair
   * @return true if the keypair is referenced in any configuration
   */
  public boolean isKeyPairReferenced(String keyPairName)
  {
    final Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();

    if (configuration.isEmpty())
    {
      return false;
    }

    Set<String> referencedKeyPairs = new LinkedHashSet<>();

    final EidasMiddlewareConfig eidasMiddlewareConfig = configuration.get();

    // Eidas config
    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = eidasMiddlewareConfig.getEidasConfiguration();
    if (eidasConfiguration != null)
    {
      referencedKeyPairs.add(eidasConfiguration.getSignatureKeyPairName());
      referencedKeyPairs.add(eidasConfiguration.getDecryptionKeyPairName());
    }

    // Eid config
    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = eidasMiddlewareConfig.getEidConfiguration();
    if (eidConfiguration != null)
    {
      for ( ServiceProviderType serviceProviderType : eidConfiguration.getServiceProvider() )
      {
        referencedKeyPairs.add(serviceProviderType.getClientKeyPairName());
      }
    }
    return referencedKeyPairs.parallelStream().anyMatch(c -> keyPairName.equals(c));
  }

  /**
   * Check if a certificate is referenced in the configuration
   * 
   * @param certificateName name of the certificate
   * @return true if the certificate is referenced in any configuration
   */
  public boolean isCertificateReferenced(String certificateName)
  {

    final Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();

    if (configuration.isEmpty())
    {
      return false;
    }

    Set<String> referencedCertifiactes = new LinkedHashSet<>();

    final EidasMiddlewareConfig eidasMiddlewareConfig = configuration.get();
    // Eidas config
    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = eidasMiddlewareConfig.getEidasConfiguration();
    if (eidasConfiguration != null)
    {
      referencedCertifiactes.add(eidasConfiguration.getMetadataSignatureVerificationCertificateName());
    }

    final EidasMiddlewareConfig.EidConfiguration eidConfiguration = eidasMiddlewareConfig.getEidConfiguration();
    if (eidConfiguration != null)
    {
      for ( DvcaConfigurationType dvcaConfigurationType : eidConfiguration.getDvcaConfiguration() )
      {
        referencedCertifiactes.add(dvcaConfigurationType.getServerSSLCertificateName());
        referencedCertifiactes.add(dvcaConfigurationType.getMasterListTrustAnchorCertificateName());
        referencedCertifiactes.add(dvcaConfigurationType.getBlackListTrustAnchorCertificateName());
      }
    }

    return referencedCertifiactes.parallelStream().anyMatch(c -> certificateName.equals(c));
  }

}
