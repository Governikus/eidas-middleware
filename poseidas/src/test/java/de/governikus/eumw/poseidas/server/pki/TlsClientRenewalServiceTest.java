package de.governikus.eumw.poseidas.server.pki;

import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;


class TlsClientRenewalServiceTest
{

  @Test
  void getSubject() throws InvalidCsrException
  {
    // Mock the configuration service
    ConfigurationService configurationService = Mockito.mock(ConfigurationService.class);

    // Just use an implementation of the abstract class
    TlsClientRenewalService tlsClientRenewalDbService = new TlsClientRenewalDbService(configurationService, null, null,
                                                                                      null, null);

    // Test missing configuration
    String subject = "subject";
    InvalidCsrException exception = Assertions.assertThrows(InvalidCsrException.class,
                                                            () -> tlsClientRenewalDbService.getSubject(subject));
    Assertions.assertEquals("The country code is missing in the configuration", exception.getMessage());

    // Test invalid country code
    EidasMiddlewareConfig config = new EidasMiddlewareConfig();
    config.setEidasConfiguration(new EidasMiddlewareConfig.EidasConfiguration(null, true, 0, "invalid", null, null,
                                                                              null, null, null, null));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));

    exception = Assertions.assertThrows(InvalidCsrException.class, () -> tlsClientRenewalDbService.getSubject(subject));
    Assertions.assertEquals("Invalid country code detected: 'invalid'", exception.getMessage());

    // Test valid country code
    config.getEidasConfiguration().setCountryCode("DE");
    X500Name x500Name = tlsClientRenewalDbService.getSubject(subject);
    Assertions.assertEquals("CN=subject TLS client authentication,O=Governikus,C=DE", x500Name.toString());
  }
}
