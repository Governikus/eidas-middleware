/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.governikus.eumw.eidascommon.Utils;


/**
 * Handles all aspects of getting the connection to the PKI service. Especially the SSL client authentication
 * is not handled properly by Metro. Current work-around is getting the WSDLs from own jar which is OK since
 * the WSDLs where already required at compile time.
 *
 * @author tautenhahn
 */
public class PKIServiceConnector
{

  private static final Log LOG = LogFactory.getLog(PKIServiceConnector.class);

  /**
   * Factor to convert seconds to milliseconds.
   */
  private static final long MILLISECOND_FACTOR = 1000L;

  /**
   * special log category to write berCA connection data and dialog content to
   */
  public static final Log SSL_LOGGER = LogFactory.getLog("de.governikus.eumw.poseidas.server.pki.debug");

  private final X509Certificate sslServersCert;

  private final KeyStore clientCertAndKey;

  private final char[] storePass;

  private final int timeout;

  private final String entityID;

  private static final char[] DUMMY_KEYPASS = "123456".toCharArray();

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
    KeyStore clientKeyStore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
    try
    {
      clientKeyStore.load(null);
    }
    catch (IOException e)
    {
      LOG.error(entityID + ": KeyStore.load threw IOException even though no load was attempted", e);
    }
    X509Certificate[] clientCertChain = sslClientCert.toArray(new X509Certificate[sslClientCert.size()]);
    clientKeyStore.setKeyEntry(entityID, sslClientKey, DUMMY_KEYPASS, clientCertChain);
    return clientKeyStore;
  }


  /**
   * Create instance with given certificates.
   *
   * @param timeout timeout in seconds
   * @param sslServersCert
   * @param clientCertAndKey
   * @param storePass
   * @throws GeneralSecurityException
   */
  public PKIServiceConnector(int timeout,
                             X509Certificate sslServersCert,
                             KeyStore clientCertAndKey,
                             char[] storePass,
                             String entityID)
    throws GeneralSecurityException
  {
    this.timeout = timeout;
    this.sslServersCert = sslServersCert;
    this.clientCertAndKey = clientCertAndKey;
    this.storePass = storePass;
    this.entityID = entityID;
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
    URL url = new URL(uri);
    URLConnection con = url.openConnection();
    con.setConnectTimeout(timeout * 1000);
    con.setReadTimeout(timeout * 1000);
    try
    {
      if (con instanceof HttpsURLConnection)
      {
        HttpsURLConnection scon = (HttpsURLConnection)con;
        scon.setSSLSocketFactory(getSSLFactory());
      }
    }
    catch (GeneralSecurityException e)
    {
      LOG.error(entityID + ": should not have happened, security stuff was done before", e);
    }
    return Utils.readBytesFromStream(con.getInputStream());
  }

  /**
   * Create an SSLSocketFactory which supports client authentication.
   *
   * @throws GeneralSecurityException
   * @throws IOException
   */
  private SSLSocketFactory getSSLFactory() throws GeneralSecurityException, IOException
  {
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");

    KeyManager km = null;
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    if (clientCertAndKey != null)
    {
      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientCertAndKey, storePass);
      X509KeyManager origKM = (X509KeyManager)kmf.getKeyManagers()[0];
      // force the key manager to use a defined key in case there is more than one
      km = new AliasKeyManager(origKM, entityID);
    }

    KeyStore trustStore = KeyStore.getInstance("jks");
    trustStore.load(null, null);
    trustStore.setCertificateEntry("alias", sslServersCert);
    tmf.init(trustStore);

    ctx.init(km == null ? null : new KeyManager[]{km}, tmf.getTrustManagers(), new SecureRandom());
    return new PoseidasSSLSocketFactory(ctx.getSocketFactory());
  }


  private static class PoseidasSSLSocketFactory extends SSLSocketFactory
  {

    private static final String[] ENABLED_CIPHER_SUITES = {
                                                           // "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                           // "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                                           "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                                           "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                                           // "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                           // "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                           "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                                                           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                                           // "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                                                           // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                                           "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                                                           "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                                                           // "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                                                           // "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                                                           "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                                                           "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                                                           "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_256_CBC_SHA",
                                                           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                                                           "TLS_RSA_WITH_AES_128_CBC_SHA"};

    private final SSLSocketFactory innerFactory;

    private PoseidasSSLSocketFactory(SSLSocketFactory inner)
    {
      this.innerFactory = inner;
    }

    @Override
    public Socket createSocket() throws IOException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket();
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket(arg0, arg1, arg2, arg3);
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1) throws IOException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket(arg0, arg1);
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket(arg0, arg1, arg2, arg3);
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3)
      throws IOException, UnknownHostException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket(arg0, arg1, arg2, arg3);
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public Socket createSocket(String arg0, int arg1) throws IOException, UnknownHostException
    {
      SSLSocket s = (SSLSocket)innerFactory.createSocket(arg0, arg1);
      s.setEnabledCipherSuites(ENABLED_CIPHER_SUITES);
      return s;
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
      return ENABLED_CIPHER_SUITES;
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
      return ENABLED_CIPHER_SUITES;
    }

    @Override
    public boolean equals(Object arg0)
    {
      return innerFactory.equals(arg0);
    }

    @Override
    public int hashCode()
    {
      return innerFactory.hashCode();
    }

    @Override
    public String toString()
    {
      return "MySSLSocketFactory: " + innerFactory.toString();
    }
  }

  /**
   * return human-readable String for identifying a certificate
   *
   * @param cert
   */
  public static String certificateToString(X509Certificate cert)
  {
    if (cert == null)
    {
      return "\tno certificate given";
    }
    StringBuilder builder = new StringBuilder();
    builder.append("\tSubjectDN: \t");
    builder.append(cert.getSubjectDN());
    builder.append("\n\tIssuerDN: \t");
    builder.append(cert.getIssuerDN());
    builder.append("\n\tSerialNumber: \t");
    builder.append(cert.getSerialNumber());
    return builder.toString();
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
                         + certificateToString((X509Certificate)clientCertAndKey.getCertificate(clientCertAndKey.aliases()
                                                                                                                .nextElement())));
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
      tlsClientParameters.setSSLSocketFactory(getSSLFactory());
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

  private static boolean sslContextLocked = false;

  private static long lockStealTime;

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
        // just continue waiting;
        LOG.error("handle me", e);
      }
      now = System.currentTimeMillis();
    }
    if (sslContextLocked)
    {
      LOG.error("stealing lock on SSL context: another thread did not release it after two minutes",
                new Exception("this is only for printing the stack trace"));
    }
    lockStealTime = System.currentTimeMillis() + 120000L;
    sslContextLocked = true;
    SSL_LOGGER.debug("Starting communication:");
  }

  /**
   * Release the lock on the SSL context - other threads may now set their static properties
   */
  public static synchronized void releaseContextLock()
  {
    SSL_LOGGER.debug("Communication finished\n\n"
                     + "######################################################################################"
                     + "\n");
    sslContextLocked = false;
    PKIServiceConnector.class.notifyAll();
  }

  /**
   * Wrap a {@link KeyManager} in order to force use of a defined key as client key.
   */
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
     * Constructor.
     *
     * @param wrapped the wrapped {@link KeyManager}
     * @param alias alias of the client key to be used
     */
    private AliasKeyManager(X509KeyManager wrapped, String alias)
    {
      this.wrapped = wrapped;
      this.alias = alias;
    }

    /** {@inheritDoc} */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
      return alias;
    }

    /** {@inheritDoc} */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
      return wrapped.chooseServerAlias(keyType, issuers, socket);
    }

    /** {@inheritDoc} */
    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
      return wrapped.getCertificateChain(alias);
    }

    /** {@inheritDoc} */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
      return wrapped.getClientAliases(keyType, issuers);
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKey getPrivateKey(String alias)
    {
      return wrapped.getPrivateKey(alias);
    }

    /** {@inheritDoc} */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
      return wrapped.getServerAliases(keyType, issuers);
    }
  }
}
