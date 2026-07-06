/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.projectconfig;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.ResourceUtils;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Configuration
public class PortCreator
{

  // PROPERTY CONSTANTS

  static final String SERVER_ADMIN_INTERFACE_PORT_PROPERTY = "server.adminInterfacePort";

  static final String SERVER_PORT_PROPERTY = "server.port";

  static final String SERVER_SSL_KEY_STORE_PROPERTY = "server.ssl.key-store";

  static final String SERVER_SSL_KEY_STORE_TYPE_PROPERTY = SERVER_SSL_KEY_STORE_PROPERTY + "-type";

  static final String SERVER_SSL_KEY_STORE_PASSWORD_PROPERTY = SERVER_SSL_KEY_STORE_PROPERTY + "-password";

  static final String SERVER_SSL_KEY_ALIAS_PROPERTY = "server.ssl.key-alias";

  static final String SERVER_SSL_CIPHERS_PROPERTY = "server.ssl.ciphers";

  static final String SERVER_SSL_ENABLED_PROTOCOLS_PROPERTY = "server.ssl.enabled-protocols";

  /**
   * The port for the admin interface
   */
  @Value("#{${" + SERVER_ADMIN_INTERFACE_PORT_PROPERTY + ":}?:0}")
  private int adminInterfacePort;

  /**
   * The port for the admin interface
   */
  @Value("${" + SERVER_PORT_PROPERTY + "}")
  private int eidasInterfacePort;

  /**
   * the path to the keystore file that is used for the TLS connections
   */
  @Value("${" + SERVER_SSL_KEY_STORE_PROPERTY + ":}")
  private String keystoreFilePath;

  /**
   * the password to access the keystore at {@link #keystoreFilePath}
   */
  @Value("${" + SERVER_SSL_KEY_STORE_PASSWORD_PROPERTY + ":}")
  private String keystorePassword;

  /**
   * the type of the given keystore at {@link #keystoreFilePath}
   */
  @Value("${" + SERVER_SSL_KEY_STORE_TYPE_PROPERTY + ":}")
  private String keystoreType;

  /**
   * the alias of the keystore entry that should be used from the keystore {@link #keystoreFilePath}
   */
  @Value("${" + SERVER_SSL_KEY_ALIAS_PROPERTY + ":}")
  private String keyAlias;

  /**
   * the maximum header size for a request / response. Default is 16kb
   */
  @Value("${server.tomcat.max-http-header-size:8192}")
  private int maxHeaderSize;

  /**
   * reads the valid ssl ciphers from the application.properties file or sets the following ciphers as default if none
   * have been entered
   */
  @Value("${" + SERVER_SSL_CIPHERS_PROPERTY + ":}")
  private String serverSslCiphers;

  /**
   * these are the supported ssl protocols that will be available on the tomcat connector
   */
  @Value("${" + SERVER_SSL_ENABLED_PROTOCOLS_PROPERTY + ":}")
  private String serverSslProtocols;

  /**
   * enable or disable TLS for both ports
   */
  @Value("${server.ssl.enabled:true}")
  private boolean serverSslEnabled;

  /**
   * Honor the cipher order on the eIDAS port.
   */
  @Bean
  public WebServerFactoryCustomizer<TomcatServletWebServerFactory> servletContainerCustomizer()
  {
    return factory -> factory.addConnectorCustomizers(connector -> {
      if (connector.getProtocolHandler() instanceof AbstractHttp11Protocol<?> httpHandler)
      {
        Arrays.stream(httpHandler.findSslHostConfigs())
              .forEach(sslHostConfig -> sslHostConfig.setHonorCipherOrder(true));
      }
    });
  }

  /**
   * creates a tomcat connector with TLS enabled for the admin interface
   */
  @Bean
  public TomcatServletWebServerFactory servletContainer() throws IOException
  {
    TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory(eidasInterfacePort);
    tomcat.setProtocol(CustomHttp11Protocol.PROTOCOL);

    if (adminInterfacePort == eidasInterfacePort || adminInterfacePort == 0)
    {
      log.error("\"%s\" must be set in application.properties and can not be same as \"%s\"!".formatted(SERVER_ADMIN_INTERFACE_PORT_PROPERTY,
                                                                                                        SERVER_PORT_PROPERTY));
      throw new IllegalStateException("\"%s\" must be set in application.properties and can not be same as \"%s\"!".formatted(SERVER_ADMIN_INTERFACE_PORT_PROPERTY,
                                                                                                                              SERVER_PORT_PROPERTY));
    }

    Connector connector = new Connector(CustomHttp11Protocol.PROTOCOL);
    connector.setPort(adminInterfacePort);

    if (serverSslEnabled)
    {
      connector.setScheme("https");
      connector.setSecure(true);
      configureSslProtocol((AbstractHttp11Protocol<?>)connector.getProtocolHandler());
    }

    tomcat.addAdditionalConnectors(connector);

    return tomcat;
  }


  /**
   * will configure the TLS protocol instance of the tomcat-connector
   *
   * @param protocol the protocol instance of the tomcat connector
   */
  private void configureSslProtocol(AbstractHttp11Protocol<?> protocol) throws IOException
  {
    protocol.setSSLEnabled(true);
    protocol.setSecure(true);
    protocol.setPort(adminInterfacePort);
    File keystoreFile = getSslConnectorKeystoreFile();

    SSLHostConfig sslHostConfig = new SSLHostConfig();

    sslHostConfig.setProtocols(serverSslProtocols);
    sslHostConfig.setEnabledProtocols(serverSslProtocols.split(","));
    sslHostConfig.setCiphers(serverSslCiphers);
    sslHostConfig.setEnabledCiphers(serverSslCiphers.split(","));
    sslHostConfig.setHonorCipherOrder(true);
    sslHostConfig.setTls13RenegotiationAvailable(false);

    sslHostConfig.addCertificate(createSslHostConfigCertificate(sslHostConfig, keystoreFile));

    protocol.addSslHostConfig(sslHostConfig);
    protocol.setMaxHttpHeaderSize(maxHeaderSize);
  }

  private @NonNull SSLHostConfigCertificate createSslHostConfigCertificate(SSLHostConfig sslHostConfig,
                                                                           File keystoreFile)
  {
    SSLHostConfigCertificate sslHostConfigCertificate = new SSLHostConfigCertificate(sslHostConfig,
                                                                                     SSLHostConfigCertificate.Type.UNDEFINED);
    sslHostConfigCertificate.setCertificateKeystoreFile(keystoreFile.getAbsolutePath());
    sslHostConfigCertificate.setCertificateKeystoreType(keystoreType);
    sslHostConfigCertificate.setCertificateKeystorePassword(keystorePassword);
    sslHostConfigCertificate.setCertificateKeyAlias(keyAlias);
    sslHostConfigCertificate.setCertificateKeyPassword(keystorePassword);
    return sslHostConfigCertificate;
  }

  /**
   * will try to get the keystore file that is used for setting up the TLS connection
   */
  private File getSslConnectorKeystoreFile() throws IOException
  {
    if (keystoreFilePath.startsWith(ResourceUtils.CLASSPATH_URL_PREFIX))
    {
      return new ClassPathResource(keystoreFilePath.substring(ResourceUtils.CLASSPATH_URL_PREFIX.length())).getFile();
    }

    if (keystoreFilePath.startsWith(ResourceUtils.FILE_URL_PREFIX))
    {
      return new File(keystoreFilePath.substring(ResourceUtils.FILE_URL_PREFIX.length()));
    }

    // NOTE:
    // If you run into this error during a spring-JUnit test use the annotation
    // @SpringBootTest instead of @ContextConfiguration
    throw new IllegalStateException("property '%s' must start with either '%s' or '%s' : %s".formatted(SERVER_SSL_KEY_STORE_PROPERTY,
                                                                                                       ResourceUtils.CLASSPATH_URL_PREFIX,
                                                                                                       ResourceUtils.FILE_URL_PREFIX,
                                                                                                       keystoreFilePath));
  }
}
