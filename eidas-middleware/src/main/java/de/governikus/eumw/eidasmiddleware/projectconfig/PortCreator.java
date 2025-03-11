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
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Configuration
public class PortCreator
{


  /**
   * The port for the admin interface
   */
  @Value("#{${server.adminInterfacePort:}?:0}")
  private int adminInterfacePort;

  /**
   * The port for the admin interface
   */
  @Value("${server.port}")
  private int eidasInterfacePort;

  /**
   * the path to the keystore file that is used for the TLS connections
   */
  @Value("${server.ssl.key-store:}")
  private String keystoreFilePath;

  /**
   * the password to access the keystore at {@link #keystorePassword}
   */
  @Value("${server.ssl.key-store-password:}")
  private String keystorePassword;

  /**
   * the type of the given keystore at {@link #keystoreFilePath}
   */
  @Value("${server.ssl.key-store-type:}")
  private String keystoreType;

  /**
   * the alias of the keystore entry that should be used from the keystore {@link #keystoreFilePath}
   */
  @Value("${server.ssl.key-alias:}")
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
  @Value("${server.ssl.ciphers:}")
  private String serverSslCiphers;

  /**
   * these are the supported ssl protocols that will be available on the tomcat connector
   */
  @Value("${server.ssl.enabled-protocols:}")
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
  public ServletWebServerFactory servletContainer()
  {
    TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();

    if (adminInterfacePort == eidasInterfacePort || adminInterfacePort == 0)
    {
      log.error("\"server.adminInterfacePort\" must be set in application.properties and can not be same as \"server.port\"!");
      throw new IllegalStateException("\"server.adminInterfacePort\" must be set in application.properties and can not be same as \"server.port\"!");
    }

    if (serverSslEnabled)
    {
      return createHttpsAdminInterfaceConnector(tomcat);
    }
    else
    {
      return createHttpAdminInterfaceConnector(tomcat);
    }
  }

  private ServletWebServerFactory createHttpAdminInterfaceConnector(TomcatServletWebServerFactory tomcat)
  {
    Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    connector.setPort(adminInterfacePort);
    tomcat.addAdditionalTomcatConnectors(connector);
    return tomcat;
  }

  private ServletWebServerFactory createHttpsAdminInterfaceConnector(TomcatServletWebServerFactory tomcat)
  {
    Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    connector.setPort(adminInterfacePort);
    connector.setScheme("https");
    connector.setSecure(true);

    Http11NioProtocol protocol = (Http11NioProtocol)connector.getProtocolHandler();
    configureSslProtocol(protocol);

    tomcat.addAdditionalTomcatConnectors(connector);
    return tomcat;
  }

  /**
   * will configure the TLS protocol instance of the tomcat-connector
   *
   * @param protocol the protocol instance of the tomcat connector
   */
  private void configureSslProtocol(Http11NioProtocol protocol)
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


    SSLHostConfigCertificate sslHostConfigCertificate = new SSLHostConfigCertificate(sslHostConfig,
                                                                                     SSLHostConfigCertificate.Type.UNDEFINED);
    sslHostConfigCertificate.setCertificateKeystoreFile(keystoreFile.getAbsolutePath());
    sslHostConfigCertificate.setCertificateKeystoreType(keystoreType);
    sslHostConfigCertificate.setCertificateKeystorePassword(keystorePassword);
    sslHostConfigCertificate.setCertificateKeyAlias(keyAlias);
    sslHostConfigCertificate.setCertificateKeyPassword(keystorePassword);

    sslHostConfig.addCertificate(sslHostConfigCertificate);

    protocol.addSslHostConfig(sslHostConfig);
    protocol.setMaxHttpHeaderSize(maxHeaderSize);
  }

  /**
   * will try to get the keystore file that is used for setting up the TLS connection
   */
  private File getSslConnectorKeystoreFile()
  {
    File keystoreFile;
    String[] keystoreFilePathParts = keystoreFilePath.split(":", 2);
    if ("classpath".equals(keystoreFilePathParts[0]))
    {
      try
      {
        keystoreFile = new ClassPathResource(keystoreFilePathParts[1]).getFile();
      }
      catch (IOException e)
      {
        throw new IllegalStateException(e.getMessage(), e);
      }
    }
    else if ("file".equals(keystoreFilePathParts[0]))
    {
      keystoreFile = new File(keystoreFilePathParts[1]);
    }
    else
    {
      // NOTE:
      // If you run into this error during a spring-JUnit test use the annotation
      // @SpringBootTest instead of @ContextConfiguration
      throw new IllegalStateException("property 'server.ssl.key-store' must start with either 'classpath:' or 'file:'"
                                      + " : " + keystoreFilePath);
    }
    return keystoreFile;
  }
}
