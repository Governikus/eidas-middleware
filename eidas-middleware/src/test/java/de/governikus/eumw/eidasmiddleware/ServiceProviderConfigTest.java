/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;


/**
 * Test that it is possible to read connector metadata
 */
@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class ServiceProviderConfigTest
{

  /**
   * mock this bean in order to point the config dir to the test resources
   */
  @MockBean
  ConfigHolder mockConfigHolder;

  @BeforeAll
  public static void setUp()
  {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Read the certificate at the given path
   */
  private X509Certificate readCertificate(File path) throws CertificateException, FileNotFoundException
  {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    FileInputStream fileInputStream = new FileInputStream(path);
    return (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
  }

  /**
   * test that a single metadata file can be read
   */
  @Test
  void testSingleMetadataFile() throws CertificateException, URISyntaxException, FileNotFoundException
  {
    URL metadataDirURL = this.getClass().getResource("/singleMetadataFile");
    Mockito.when(mockConfigHolder.getProviderConfigDir()).thenReturn(new File(metadataDirURL.toURI()));
    URL sigCertURL = this.getClass().getResource("/singleMetadataFile/generated_metadata.crt");
    Mockito.when(mockConfigHolder.getMetadataSignatureCert())
           .thenReturn(readCertificate(new File(sigCertURL.toURI())));

    ServiceProviderConfig config = new ServiceProviderConfig(mockConfigHolder);
    Assertions.assertNotNull(config.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"),
                             "Metadata expected");
  }

  /**
   * Test that it is possible to read multiple metadata files
   */
  @Test
  void testTwoMetadataFiles() throws CertificateException, URISyntaxException, FileNotFoundException
  {
    URL metadataDirURL = this.getClass().getResource("/twoMetadataFiles");
    Mockito.when(mockConfigHolder.getProviderConfigDir()).thenReturn(new File(metadataDirURL.toURI()));
    URL sigCertURL = this.getClass().getResource("/twoMetadataFiles/sigCert.crt");
    Mockito.when(mockConfigHolder.getMetadataSignatureCert())
           .thenReturn(readCertificate(new File(sigCertURL.toURI())));

    ServiceProviderConfig config = new ServiceProviderConfig(mockConfigHolder);
    Assertions.assertNotNull(config.getProviderByEntityID("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_20"),
                             "First metadata expected");
    Assertions.assertNotNull(config.getProviderByEntityID("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa"),
                             "Second metadata expected");
  }

  /**
   * Test that a missing or wrong certificate is detected
   */
  @Test
  void missingSignatureCertificate() throws CertificateException, URISyntaxException, FileNotFoundException
  {
    URL metadataDirURL = this.getClass().getResource("/singleMetadataFile");
    Mockito.when(mockConfigHolder.getProviderConfigDir()).thenReturn(new File(metadataDirURL.toURI()));
    Mockito.when(mockConfigHolder.getMetadataSignatureCert()).thenReturn(null);

    Assertions.assertThrows(BadConfigurationException.class,
                            () -> new ServiceProviderConfig(mockConfigHolder),
                            "Exception expected as no metadata signature cert is given");

    URL sigCertURL = this.getClass().getResource("/twoMetadataFiles/sigCert.crt");
    Mockito.when(mockConfigHolder.getMetadataSignatureCert())
           .thenReturn(readCertificate(new File(sigCertURL.toURI())));

    Assertions.assertThrows(BadConfigurationException.class,
                            () -> new ServiceProviderConfig(mockConfigHolder),
                            "Exception expected as the wrong signature cert is given");
  }

}
