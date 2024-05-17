/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import de.governikus.eumw.poseidas.server.pki.caserviceaccess.logging.MessageLoggingInterceptor;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.WebServiceException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.tomcat.util.net.Constants;
import org.bouncycastle.jsse.util.SNISocketFactory;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.RequiredArgsConstructor;


/**
 * Handles all aspects of getting the connection to the PKI service. Especially the SSL client authentication
 * is not handled properly by Metro. Current work-around is getting the WSDLs from own jar which is OK since
 * the WSDLs where already required at compile time.
 *
 * @author tautenhahn
 */
public class PKIServiceConnector
{

  /**
   * special log category to write berCA connection data and dialog content to
   */
  private static final Log SSL_LOGGER = LogFactory.getLog("de.governikus.eumw.poseidas.server.pki.debug");

  private static final Log LOG = LogFactory.getLog(PKIServiceConnector.class);

  /**
   * Factor to convert seconds to milliseconds.
   */
  private static final long MILLISECOND_FACTOR = 1000L;

  private static final String[] ENABLED_CIPHER_SUITES = {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                                         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                                         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                                                         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                                         "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                                                         "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                                         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                                                         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                                                         "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                                                         "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                                                         "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                                                         "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"};

  private static final char[] DUMMY_KEYPASS = "123456".toCharArray();

  private static final String DVCA_MTLS_ALIAS = "dvca-mtls";

  private static boolean sslContextLocked = false;

  private static long lockStealTime;

  private final X509Certificate sslServersCert;

  private final KeyStore clientCertAndKey;

  private final char[] storePass;

  private final int timeout;

  private final String entityID;

  private final boolean hsmMode;


  /**
   * Create new instance for specifies SSL parameters
   *
   * @param timeout in seconds
   * @param sslServerCert
   * @param sslClientCert specify whole certificate chain if you like
   * @param sslClientKey
   * @throws GeneralSecurityException
   */
  public PKIServiceConnector(int timeout,
                             X509Certificate sslServerCert,
                             Key sslClientKey,
                             List<X509Certificate> sslClientCert,
                             String entityID)
    throws GeneralSecurityException
  {
    this(timeout, sslServerCert, createKeystore(sslClientKey, sslClientCert, entityID), DUMMY_KEYPASS,
         entityID);
  }

  /**
   * Create instance with given certificates.
   *
   * @param timeout timeout in seconds
   * @param sslServersCert
   * @param clientCertAndKey
   * @param storePass
   * @param entityID
   */
  public PKIServiceConnector(int timeout,
                             X509Certificate sslServersCert,
                             KeyStore clientCertAndKey,
                             char[] storePass,
                             String entityID)
  {
    this.timeout = timeout;
    this.sslServersCert = sslServersCert;
    this.clientCertAndKey = clientCertAndKey;
    this.storePass = storePass;
    this.entityID = entityID;
    this.hsmMode = clientCertAndKey.getProvider().getName().startsWith("SunPKCS11-");
  }

  private static KeyStore createKeystore(Key sslClientKey,
                                         List<X509Certificate> sslClientCert,
                                         String entityID)
    throws GeneralSecurityException
  {
    if (sslClientKey == null)
    {
      return null;
    }

    // Must use bouncy as SUN Provider changes alias to lower case
    KeyStore clientKeyStore = KeyStore.getInstance("pkcs12", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    try
    {
      clientKeyStore.load(null);
    }
    catch (IOException e)
    {
      LOG.error(entityID + ": KeyStore.load threw IOException even though no load was attempted", e);
    }
    X509Certificate[] clientCertChain = sslClientCert.toArray(new X509Certificate[sslClientCert.size()]);
    // The BC JSSE Provider in version 1.66 manipulates the alias of the key store. For example 'test.alias' will be changed to '0.test.alias.1'
    // Later when the private key entry will be loaded, the alias will be changed again. Theoretically the alias should be the same again,
    // but unfortunately the method to build the alias search for '.' only from the beginning. So the alias '0.test.alias.1'
    // will be just 'test' and not 'test.alias'. When an entity has '.' in the name, BC will not find the private key entry.
    // Therefore, we change the alias to constant value.
    // See ProvX509KeyManager#loadPrivateKeyEntry BC version 1.66
    clientKeyStore.setKeyEntry(DVCA_MTLS_ALIAS, sslClientKey, DUMMY_KEYPASS, clientCertChain);
    return clientKeyStore;
  }

  /**
   * return human-readable String for identifying a certificate
   *
   * @param cert
   */
  private static String certificateToString(X509Certificate cert)
  {
    if (cert == null)
    {
      return "\tno certificate given";
    }
    StringBuilder builder = new StringBuilder();
    builder.append("\tSubjectDN: \t")
           .append(cert.getSubjectDN())
           .append("\n\tIssuerDN: \t")
           .append(cert.getIssuerDN())
           .append("\n\tSerialNumber: \t")
           .append(cert.getSerialNumber());
    return builder.toString();
  }

  /**
   * Block as long as another thread uses the SSL context. After calling this method, a client can set its own
   * static properties to the SSL context without breaking some other process.
   */
  public static synchronized void getContextLock()
  {
    long now = System.currentTimeMillis();
    while (sslContextLocked && now < lockStealTime)
    {
      try
      {
        PKIServiceConnector.class.wait(lockStealTime - now);
      }
      catch (InterruptedException e)
      {
        LOG.error("Thread was interrupted while waiting for the SSL context lock", e);
        // Reinterrupt the current thread to make sure we are not ignoring the interrupt signal
        Thread.currentThread().interrupt();
      }
      now = System.currentTimeMillis();
    }
    if (sslContextLocked)
    {
      LOG.error("stealing lock on SSL context: another thread did not release it after two minutes",
                new Exception("this is only for printing the stack trace"));
    }
    final long twoMinutesInMillis = 2 * 60 * 1000L;
    lockStealTime = System.currentTimeMillis() + twoMinutesInMillis;
    sslContextLocked = true;
    SSL_LOGGER.debug("Starting communication");
  }

  /**
   * Release the lock on the SSL context - other threads may now set their static properties
   */
  public static synchronized void releaseContextLock()
  {
    SSL_LOGGER.debug("Communication finished");
    sslContextLocked = false;
    PKIServiceConnector.class.notifyAll();
  }

  /**
   * Get a document (usually a WSDL) via configured transport HTTP GET and return the content.
   *
   * @param uri
   * @throws URISyntaxException
   * @throws IOException
   */
  public byte[] getFile(String uri) throws IOException
  {
    CloseableHttpClient client;
    try
    {
      SSLContext ctx = createSSLContext();
      SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(ctx,
                                                                                   new String[]{Constants.SSL_PROTO_TLSv1_2},
                                                                                   ENABLED_CIPHER_SUITES,
                                                                                   SSLConnectionSocketFactory.getDefaultHostnameVerifier());
      client = HttpClients.custom().useSystemProperties().setSSLSocketFactory(sslSocketFactory).build();
    }
    catch (CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException
      | KeyManagementException | NoSuchProviderException e)
    {
      throw new IOException("Cannot create http client", e);
    }
    try (CloseableHttpResponse response = client.execute(new HttpGet(uri)))
    {
      return Utils.readBytesFromStream(response.getEntity().getContent());
    }
  }

  private SSLContext createSSLContext() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException,
    KeyManagementException, IOException, CertificateException, NoSuchProviderException
  {
    SSLContext ctx = SSLContext.getInstance(Constants.SSL_PROTO_TLSv1_2,
                                            hsmMode ? SecurityProvider.SUN_JSSE_PROVIDER
                                              : SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER);
    KeyManager[] km = createKeyManager();
    ctx.init(km, createTrustManager(), new SecureRandom());
    return ctx;
  }

  private TrustManager[] createTrustManager()
    throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, NoSuchProviderException
  {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(),
                                                              hsmMode ? SecurityProvider.SUN_JSSE_PROVIDER
                                                                : SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER);
    KeyStore trustStore = KeyStore.getInstance("jks");
    trustStore.load(null, null);
    trustStore.setCertificateEntry("alias", sslServersCert);
    tmf.init(trustStore);
    return tmf.getTrustManagers();
  }

  private KeyManager[] createKeyManager() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException
  {
    KeyManagerFactory kmf;
    if (hsmMode)
    {
      LOG.debug("HSM Mode is true. Use SunJSSE Provider");
      kmf = KeyManagerFactory.getInstance("SUNX509", SecurityProvider.SUN_JSSE_PROVIDER);
    }
    else
    {
      LOG.debug("HSM Mode is false. " + SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER);
      kmf = KeyManagerFactory.getInstance("PKIX", SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER);
    }
    kmf.init(clientCertAndKey, storePass);
    if (hsmMode)
    {
      LOG.debug("HSM Mode is true. Use AliasKeyManager");
      X509KeyManager origKM = (X509KeyManager)kmf.getKeyManagers()[0];
      // force the key manager to use a defined key in case there is more than one
      KeyManager km = new AliasKeyManager(origKM, entityID);
      return new KeyManager[]{km};
    }
    return kmf.getKeyManagers();
  }

  void setHttpsConnectionSetting(BindingProvider port, String uri) throws URISyntaxException
  {
    try
    {
      SSL_LOGGER.debug(entityID + ": Creating https connection with client authentication to " + uri);
      SSL_LOGGER.debug(entityID + ": Trusted SSL server certificate:\n"
                       + certificateToString(sslServersCert));
      if (clientCertAndKey != null)
      {
        SSL_LOGGER.debug(entityID + ": Certificate for SSL client key:\n"
                         + certificateToString((X509Certificate)clientCertAndKey.getCertificate(DVCA_MTLS_ALIAS)));
      }
      else
      {
        SSL_LOGGER.error(entityID + ": No Client SSL key given");
      }
    }
    catch (KeyStoreException e)
    {
      SSL_LOGGER.error(entityID + ": can not read out certificate", e);
    }
    try
    {
      if (uri.startsWith("http://"))
      {
        return;
      }

      port.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, uri);

      HTTPConduit conduit = (HTTPConduit)ClientProxy.getClient(port).getConduit();
      HTTPClientPolicy policy = new HTTPClientPolicy();
      policy.setConnectionTimeout(MILLISECOND_FACTOR * timeout);
      policy.setReceiveTimeout(MILLISECOND_FACTOR * timeout);
      conduit.setClient(policy);
      TLSClientParameters tlsClientParameters = new TLSClientParameters();
      SSLContext sslContext = createSSLContext();
      URI serverURI = new URI(uri);
      // CXF uses the SocketFactory from the TLSClientParamters for the HttpsURLConnection. The default
      // ProvSSLContextSpi does not use an SNI (Server Name Indication) for the connection. This can lead to problems if
      // the DVCA is running on a server on which several domains are accessible under the same IP address, but these
      // have different TLS certificates. This can lead to the server displaying the wrong TLS certificate. The
      // SNISocketFactory must be used for SNI to be used.
      tlsClientParameters.setSSLSocketFactory(new SNISocketFactory(sslContext.getSocketFactory(), serverURI.toURL()));
      tlsClientParameters.setCipherSuites(Arrays.asList(ENABLED_CIPHER_SUITES));
      conduit.setTlsClientParameters(tlsClientParameters);
    }
    catch (WebServiceException e)
    {
      if (e.getCause() instanceof URISyntaxException)
      {
        throw (URISyntaxException)e.getCause();
      }
      throw e;
    }
    catch (GeneralSecurityException e)
    {
      LOG.error(entityID + ": should not have happened because certs and keys were already parsed", e);
    }
    catch (IOException e)
    {
      LOG.error(entityID + ": should not have happened because no I/O is done", e);
    }
  }

  void setMessageLogger(BindingProvider port)
  {
    Client cxfClient = ClientProxy.getClient(port);
    cxfClient.getOutInterceptors().add(new MessageLoggingInterceptor());
    cxfClient.getInInterceptors().add(new MessageLoggingInterceptor());
  }

  /**
   * Wrap a {@link KeyManager} in order to force use of a defined key as client key.
   */
  @RequiredArgsConstructor
  private static final class AliasKeyManager implements X509KeyManager
  {

    /**
     * Wrapped {@link KeyManager}.
     */
    private final X509KeyManager wrapped;

    /**
     * Alias of the client key.
     */
    private final String alias;

    /**
     * {@inheritDoc}
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
      return alias;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
      return wrapped.chooseServerAlias(keyType, issuers, socket);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
      return wrapped.getCertificateChain(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
      return wrapped.getClientAliases(keyType, issuers);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PrivateKey getPrivateKey(String alias)
    {
      return wrapped.getPrivateKey(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
      return wrapped.getServerAliases(keyType, issuers);
    }
  }
}
