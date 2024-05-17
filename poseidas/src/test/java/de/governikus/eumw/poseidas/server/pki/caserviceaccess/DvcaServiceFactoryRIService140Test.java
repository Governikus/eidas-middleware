package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;


@SpringBootTest
@ContextConfiguration(classes = {DvcaServiceFactory.class})
@TestPropertySource(properties = """
  poseidas.ri-service.1-40 = true
  """)
class DvcaServiceFactoryRIService140Test
{

  @Autowired
  DvcaServiceFactory dvcaServiceFactory;

  @MockBean
  ConfigurationService configurationService;

  @Test
  void testUseRiService140() throws Exception
  {
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createConfigurationWithClientKeyPair();

    DvcaConfigurationType dvcaConfigurationType = configuration.getEidConfiguration().getDvcaConfiguration().get(0);
    ServiceProviderType serviceProviderType = configuration.getEidConfiguration()
                                                           .getServiceProvider()
                                                           .stream()
                                                           .filter(sp -> sp.getName()
                                                                           .equals(ConfigurationTestHelper.SP_NAME))
                                                           .findFirst()
                                                           .orElseThrow();
    Mockito.when(configurationService.getDvcaConfiguration(serviceProviderType)).thenReturn(dvcaConfigurationType);
    Mockito.when(configurationService.getKeyPair(serviceProviderType.getClientKeyPairName()))
           .thenReturn(ConfigurationTestHelper.getKeyPair(serviceProviderType.getClientKeyPairName(), configuration));
    RestrictedIdService restrictedIdService = dvcaServiceFactory.createRestrictedIdService(serviceProviderType, null);
    Assertions.assertInstanceOf(RestrictedIdService140.class, restrictedIdService);
  }
}
