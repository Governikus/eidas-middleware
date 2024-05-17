package de.governikus.eumw.poseidas.server.pki;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.assertj.core.util.DateUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaServiceFactory;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;


@ExtendWith(MockitoExtension.class)
class CvcEntanglementServiceTest
{

  @Mock
  TermAuthService termAuthService;

  @Mock
  CvcTlsCheck cvcTlsCheck;

  @Mock
  ConfigurationService configurationService;

  @Mock
  TerminalPermissionAO facade;

  @Mock
  DvcaServiceFactory dvcaServiceFactory;

  @Mock
  RequestSignerCertificateService requestSignerCertificateService;

  @Mock
  TimerHistoryService timerHistoryService;

  @InjectMocks
  CvcEntanglementService entanglementService;



  @BeforeEach
  void setUp() throws Exception
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = Mockito.mock(EidasMiddlewareConfig.class);
    Mockito.when(eidasMiddlewareConfig.getServerUrl()).thenReturn("https://serverUrl");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));

    EidasMiddlewareConfig.EidConfiguration eidConfiguration = Mockito.mock(EidasMiddlewareConfig.EidConfiguration.class);
    Mockito.when(eidasMiddlewareConfig.getEidConfiguration()).thenReturn(eidConfiguration);

    ServiceProviderType serviceProvider1 = Mockito.mock(ServiceProviderType.class);
    Mockito.when(serviceProvider1.isEnabled()).thenReturn(false);

    ServiceProviderType serviceProvider2 = Mockito.mock(ServiceProviderType.class);
    Mockito.when(serviceProvider2.isEnabled()).thenReturn(true);

    ServiceProviderType serviceProvider3 = Mockito.mock(ServiceProviderType.class);
    Mockito.when(serviceProvider3.getCVCRefID()).thenReturn("serviceProvider3");
    Mockito.when(serviceProvider3.getDvcaConfigurationName()).thenReturn("noop");
    Mockito.when(serviceProvider3.isEnabled()).thenReturn(true);

    ServiceProviderType serviceProvider4 = Mockito.mock(ServiceProviderType.class);
    Mockito.when(serviceProvider4.isEnabled()).thenReturn(true);

    Mockito.when(eidConfiguration.getServiceProvider())
           .thenReturn(List.of(serviceProvider1, serviceProvider2, serviceProvider3, serviceProvider4));

    X509Certificate serverCertificate = Mockito.mock(X509Certificate.class);
    // Valid server certificate;
    Mockito.when(serverCertificate.getNotAfter()).thenReturn(DateUtil.tomorrow());
    Mockito.when(serverCertificate.getEncoded()).thenReturn(new byte[]{1, 2, 3});

    Mockito.when(cvcTlsCheck.getOwnTlsCertificate(Mockito.anyString())).thenReturn(Optional.of(serverCertificate));
    Mockito.when(cvcTlsCheck.getCvcResultsForSp(Mockito.eq(serviceProvider2), Mockito.any(), Mockito.any()))
           .thenReturn(CvcTlsCheck.CvcCheckResults.builder().cvcPresent(true).cvcTlsMatch(true).build());
    Mockito.when(cvcTlsCheck.getCvcResultsForSp(Mockito.eq(serviceProvider3), Mockito.any(), Mockito.any()))
           .thenReturn(CvcTlsCheck.CvcCheckResults.builder().cvcPresent(true).cvcTlsMatch(false).build());
    Mockito.when(cvcTlsCheck.getCvcResultsForSp(Mockito.eq(serviceProvider4), Mockito.any(), Mockito.any()))
           .thenReturn(CvcTlsCheck.CvcCheckResults.builder().cvcPresent(false).cvcTlsMatch(false).build());

    TerminalPermission terminalPermissionSp3 = Mockito.mock(TerminalPermission.class);
    RequestSignerCertificate rscSp3 = Mockito.mock(RequestSignerCertificate.class);

    Mockito.when(terminalPermissionSp3.getCurrentRequestSignerCertificate()).thenReturn(rscSp3);
    byte[] cvc = getResourceAsByteArray("/terminalCertificates/terminalCert.cvc");
    Mockito.when(terminalPermissionSp3.getCvc()).thenReturn(cvc);
    Mockito.when(terminalPermissionSp3.getNotOnOrAfter()).thenReturn(new Date(System.currentTimeMillis() + 50_000));

    Mockito.when(facade.getTerminalPermission(serviceProvider3.getCVCRefID())).thenReturn(terminalPermissionSp3);

    Mockito.when(dvcaServiceFactory.createTermAuthService(Mockito.any(), Mockito.any())).thenReturn(termAuthService);
    Mockito.when(termAuthService.getCACertificates()).thenReturn(new byte[][]{});

    Mockito.when(requestSignerCertificateService.signCmsContainer(Mockito.any(), Mockito.any(), Mockito.any()))
           .thenReturn(Optional.of(new byte[0]));
  }


  @Test
  void checkEntanglement() throws Exception
  {
    List<ServiceProviderType> entanglementIsNecessary = entanglementService.getSpWhereEntanglementIsNecessary(cvcTlsCheck.getOwnTlsCertificate(""),
                                                                                                              entanglementService.getActiveServiceProviders());
    Assertions.assertEquals(1, entanglementIsNecessary.size());

    ManagementMessage managementMessage = entanglementService.checkEntanglement()
                                                             .get(configurationService.getConfiguration()
                                                                                      .get()
                                                                                      .getEidConfiguration()
                                                                                      .getServiceProvider()
                                                                                      .get(2));
    // expect failure in successive request
    assertEquals(GlobalManagementCodes.EC_UNEXPECTED_ERROR, managementMessage.getCode());
    assertEquals("no suitable certificate stored in chain", managementMessage.getDetails());

    Mockito.verify(cvcTlsCheck, Mockito.atLeastOnce()).getOwnTlsCertificate(Mockito.anyString());
    Mockito.verify(termAuthService, Mockito.atLeastOnce()).sendeIDServerCerts(Mockito.any());
    Mockito.verify(facade, Mockito.atLeastOnce()).archiveCVC(Mockito.any(), Mockito.any());
  }

  private byte[] getResourceAsByteArray(String path) throws Exception
  {
    try (InputStream resourceAsStream = TerminalPermissionAOBeanTest.class.getResourceAsStream(path))
    {
      return resourceAsStream.readAllBytes();
    }
  }
}
