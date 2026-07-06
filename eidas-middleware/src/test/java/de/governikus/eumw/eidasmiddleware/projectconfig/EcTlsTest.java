package de.governikus.eumw.eidasmiddleware.projectconfig;

import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_ADMIN_INTERFACE_PORT_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_PORT_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_CIPHERS_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_ENABLED_PROTOCOLS_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_KEY_ALIAS_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_KEY_STORE_PASSWORD_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_KEY_STORE_PROPERTY;
import static de.governikus.eumw.eidasmiddleware.projectconfig.PortCreator.SERVER_SSL_KEY_STORE_TYPE_PROPERTY;
import static org.apache.tomcat.util.net.Constants.SSL_PROTO_TLSv1_2;
import static org.apache.tomcat.util.net.Constants.SSL_PROTO_TLSv1_3;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServer;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.TestSocketUtils;
import org.springframework.util.ResourceUtils;

import de.governikus.eumw.eidasmiddleware.EIDASMiddlewareApplication;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;

import liquibase.util.NetUtil;
import lombok.SneakyThrows;


/**
 * Starts a tomcat web server configured by the {@link PortCreator} and tests TLS handshakes.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // Necessary for using @BeforeAll as none static
@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = {EcTlsTest.EcTlsTestPropertiesConfiguration.class}, classes = {PortCreator.class})
final class EcTlsTest
{

  @Value("${" + SERVER_ADMIN_INTERFACE_PORT_PROPERTY + "}")
  int port;

  @Autowired
  PortCreator portCreator;

  Runnable stopWebserver = () -> {}; // function to stop the web server

  // Prepare system security properties
  static
  {
    EIDASMiddlewareApplication.prepareConfigurationContext();
  }

  /**
   * Starts a tomcat web server prepared by our {@link PortCreator} once before all tests
   */
  @BeforeAll
  @SneakyThrows
  void startWebserver()
  {
    TomcatServletWebServerFactory tomcatServletWebServerFactory = portCreator.servletContainer();
    portCreator.servletContainerCustomizer().customize(tomcatServletWebServerFactory);
    WebServer webServer = tomcatServletWebServerFactory.getWebServer();
    stopWebserver = webServer::stop;
    webServer.start();
  }

  /**
   * Stops the tomcat web server after all tests
   */
  @AfterAll
  void stopWebserver()
  {
    stopWebserver.run();
  }

  /**
   * Created an SSL client socket to the web server and tries an SSL handshake. The SSL client is limited to the given
   * curve.
   *
   * @param curveName the curve the client shall use only.
   */
  @SneakyThrows
  @ParameterizedTest
  @ValueSource(strings = {"brainpoolP512r1", "brainpoolP384r1", "brainpoolP256r1", "secp521r1", "secp384r1",
                          "secp256r1"})
  void testTlsHandshake(String curveName)
  {
    try (
      SSLSocket clientSslSocket = (SSLSocket)prepareBrainpoolSocketFactory().createSocket(NetUtil.getLocalHostAddress(),
                                                                                          port))
    {
      SSLParameters params = clientSslSocket.getSSLParameters();
      params.setNamedGroups(new String[]{curveName});

      clientSslSocket.setSSLParameters(params);
      clientSslSocket.setSoTimeout(1_000); // 1 second

      Assertions.assertDoesNotThrow(clientSslSocket::startHandshake);
    }
  }

  /**
   * Creates an SSL context for the client socket.
   */
  private static SSLSocketFactory prepareBrainpoolSocketFactory()
    throws NoSuchAlgorithmException, KeyManagementException
  {
    SSLContext sslContext = SSLContext.getInstance(SSL_PROTO_TLSv1_2, SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER);
    sslContext.init(null, new TrustManager[]{getNoopTrustManager()}, null);
    return sslContext.getSocketFactory();
  }

  /**
   * Creates a trust manager that trusts any certificate.
   */
  private static @NonNull X509TrustManager getNoopTrustManager()
  {
    return new X509TrustManager()
    {

      @Override
      public void checkClientTrusted(X509Certificate[] chain, String authType)
      {
        // NOOP
      }

      @Override
      public void checkServerTrusted(X509Certificate[] chain, String authType)
      {
        // NOOP
      }

      @Override
      public X509Certificate[] getAcceptedIssuers()
      {
        return new X509Certificate[0];
      }
    };
  }

  /**
   * Sets the properties for this tests spring context
   */
  static class EcTlsTestPropertiesConfiguration implements ApplicationContextInitializer<ConfigurableApplicationContext>
  {

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext)
    {
      Map<String, Object> properties = new HashMap<>();

      properties.put(SERVER_PORT_PROPERTY, TestSocketUtils.findAvailableTcpPort());
      properties.put(SERVER_ADMIN_INTERFACE_PORT_PROPERTY, TestSocketUtils.findAvailableTcpPort());
      properties.put(SERVER_SSL_KEY_STORE_PROPERTY, ResourceUtils.CLASSPATH_URL_PREFIX + "brainpool/brainpool.p12");
      properties.put(SERVER_SSL_KEY_ALIAS_PROPERTY, "eumw-tls-brainpool-512-test");
      properties.put(SERVER_SSL_KEY_STORE_PASSWORD_PROPERTY, "123456");
      properties.put(SERVER_SSL_KEY_STORE_TYPE_PROPERTY, KeyStoreSupporter.KeyStoreType.PKCS12.name());
      properties.put(SERVER_SSL_CIPHERS_PROPERTY,
                     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_SHA256");
      properties.put(SERVER_SSL_ENABLED_PROTOCOLS_PROPERTY, String.join(",", SSL_PROTO_TLSv1_2, SSL_PROTO_TLSv1_3));

      applicationContext.getEnvironment().getPropertySources().addFirst(new MapPropertySource("testprops", properties));
    }
  }
}
