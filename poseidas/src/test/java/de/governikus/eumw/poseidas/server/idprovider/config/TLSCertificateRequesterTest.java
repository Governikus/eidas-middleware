package de.governikus.eumw.poseidas.server.idprovider.config;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.mockserver.configuration.Configuration;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.junit.jupiter.MockServerExtension;


@ExtendWith({MockServerExtension.class, MockitoExtension.class})
class TLSCertificateRequesterTest
{

  @Mock
  ServerTlsCertificateSelector serverTlsCertificateSelector;

  @InjectMocks
  TLSCertificateRequester tlscertificateRequester;

  Path resourceDirectory = Paths.get("src", "test", "resources");

  @BeforeEach
  void setUp()
  {
    // Always select first certificate as tls server certificate
    Mockito.when(serverTlsCertificateSelector.selectServerTlsCertificate(Mockito.any()))
           .thenAnswer((Answer<Optional<X509Certificate>>)invocation -> {
             List<X509Certificate> certificates = invocation.getArgument(0);
             return Optional.of(certificates.getFirst());
           });
  }

  @Test
  void testCertificateRequesting()
  {
    Configuration configuration = Configuration.configuration();
    configuration.x509CertificatePath(resourceDirectory + "/test-tls-certificates/server.cert");
    configuration.privateKeyPath(resourceDirectory + "/test-tls-certificates/server.p8.pem");
    configuration.certificateAuthorityCertificate(resourceDirectory + "/test-tls-certificates/sub_ca.cert");

    try (ClientAndServer clientAndServer = ClientAndServer.startClientAndServer(configuration))
    {
      Optional<X509Certificate> optionalCertificate = tlscertificateRequester.requestTlsServerCertificate("https://localhost:"
                                                                                                          + clientAndServer.getLocalPort());
      Assertions.assertTrue(optionalCertificate.isPresent());
    }
  }
}
