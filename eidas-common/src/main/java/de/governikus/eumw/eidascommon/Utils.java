/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidascommon;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.UUID;
import java.util.zip.ZipInputStream;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import jakarta.servlet.http.HttpServletRequest;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;


/**
 * Helper methods needed for creating and parsing SAML messages.
 *
 * @author TT, hauke
 */
@Slf4j
public final class Utils
{

  /**
   * Minimal size for RSA keys (SAML).
   */
  private static final int MIN_KEY_SIZE_RSA_SAML = 3072;

  /**
   * Minimal size for EC keys (SAML).
   */
  private static final int MIN_KEY_SIZE_EC_SAML = 256;

  /**
   * Minimal size for RSA keys (TLS).
   */
  public static final int MIN_KEY_SIZE_RSA_TLS = 2048;

  /**
   * Minimal size for EC keys (TLS).
   */
  public static final int MIN_KEY_SIZE_EC_TLS = 224;

  /**
   * default encoding used by the eID-Server
   */
  public static final String ENCODING = StandardCharsets.UTF_8.name();

  /**
   * Contains a error page to show if something went wrong.
   */
  private static final String HTML_ERROR = loadHTMLErrorPage();

  /**
   * XML feature to disallow doctype declarations
   */
  private static final String DISALLOW_DOCTYPE_DECL = "http://apache.org/xml/features/disallow-doctype-decl";

  /**
   * XML feature to disallow external general entities
   */
  private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";

  /**
   * Load the error page.
   */
  private static String loadHTMLErrorPage()
  {
    try
    {
      return Utils.readFromStream(Utils.class.getResourceAsStream("error.html"));
    }
    catch (IOException e)
    {
      // OK, no nice page then
      return "${MESSAGE}";
    }
  }

  private Utils()
  {
    super();
  }

  /**
   * An instance of this class hold a X.509 certificate and its private Key.
   *
   * @author hauke
   */
  public static class X509KeyPair
  {

    private final PrivateKey key;

    private final X509Certificate[] chain;

    public X509KeyPair(PrivateKey key, X509Certificate[] chain)
    {
      this.key = key;
      this.chain = chain;
    }

    private X509KeyPair(PrivateKey key, X509Certificate cert)
    {
      this.key = key;
      this.chain = (cert == null) ? null : new X509Certificate[]{cert};
    }

    /**
     * Returns the private key
     */
    public PrivateKey getKey()
    {
      return key;
    }

    /**
     * Returns the certificate for the private Key
     */
    public X509Certificate getCert()
    {
      return (chain == null || chain.length == 0) ? null : chain[0];
    }

    /**
     * Returns the certificate of the private key and its certificate chain.
     */
    public X509Certificate[] getChain()
    {
      return chain;
    }

    @Override
    public int hashCode()
    {
      final int prime = 31;
      int result = 1;
      result = prime * result + Arrays.hashCode(chain);
      result = prime * result + ((key == null) ? 0 : key.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj)
    {
      if (this == obj)
      {
        return true;
      }
      if (obj == null || getClass() != obj.getClass())
      {
        return false;
      }
      X509KeyPair other = (X509KeyPair)obj;
      if (chain == null)
      {
        if (other.chain != null)
        {
          return false;
        }
      }
      else if (!Arrays.equals(chain, other.chain))
      {
        return false;
      }
      if (key == null)
      {
        if (other.key != null)
        {
          return false;
        }
      }
      else if (!key.equals(other.key))
      {
        return false;
      }
      return true;
    }

    @Override
    public String toString()
    {
      return "X509KeyPair [key=" + key + ", chain=" + Arrays.toString(chain) + "]";
    }

  }

  /**
   * Return a String which fulfills the uniqueness requirements stated in saml-core20-os.
   */
  public static String generateUniqueID()
  {
    return UUID.randomUUID().toString();
  }

  /**
   * Read all bytes from a given stream
   *
   * @param ins input to read - will be closed by this method if doClose is true
   * @return contained data
   */
  private static ByteArrayOutputStream readBoutFromStream(InputStream ins, boolean doClose) throws IOException
  {
    byte[] inBytes = new byte[1024];
    ByteArrayOutputStream outs = new ByteArrayOutputStream();
    int numReadBytes = ins.read(inBytes);

    while (numReadBytes > 0)
    {
      outs.write(inBytes, 0, numReadBytes);
      numReadBytes = ins.read(inBytes);
    }
    if (doClose)
    {
      ins.close();
    }

    return outs;
  }

  /**
   * Read everything from given input stream into a String using default encoding.
   *
   * @param ins is closed if OK
   * @return UTF-8 encoded String
   * @throws IOException fall thru
   */
  public static String readFromStream(InputStream ins) throws IOException
  {
    return readBoutFromStream(ins, true).toString(ENCODING);
  }

  /**
   * Read everything from given input stream into a byte array.
   *
   * @param ins is closed if OK
   * @return freshly created byte array
   * @throws IOException fallthru
   */
  public static byte[] readBytesFromStream(InputStream ins) throws IOException
  {
    return readBoutFromStream(ins, true).toByteArray();
  }


  /**
   * Read everything from given input stream into a byte array but do not close the stream. This is
   *
   * @param ins
   * @return freshly created byte array
   * @throws IOException fallthru
   */
  public static byte[] readBytesFromStream(ZipInputStream ins) throws IOException
  {
    return readBoutFromStream(ins, false).toByteArray();
  }


  /**
   * Read a key and certificate form a given input stream. When reading a pem file it does only work for pem files
   * containing not more than one certificate and one private key. Providing more causes unpredictable behavior. Pem
   * file containing only a private key or only a certificate are also supported. Reading of pem files is not supported
   * with java 1.5 (also, java 1.5 needs endorsed xerces!)
   *
   * @param ins stream to read the keystore or PEM from
   * @param type keystore type, i.e. "PKCS12", "JKS" or "PEM"
   * @param pin keystore password
   * @param alias alias of the requested key pair. If a wrong value is given, look at stderr to see the available
   *          aliases. The alias parameter is not supported for pem files.
   * @param keyPin key password
   */
  private static X509KeyPair readKeyAndCert(InputStream ins, String type, char[] pin, String alias, char[] keyPin)
    throws IOException, GeneralSecurityException
  {
    if (ins == null)
    {
      throw new NullPointerException("input stream to load key and cert from cannot be null");
    }

    KeyStore keyStore;
    try
    {
      keyStore = KeyStore.getInstance(type, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    catch (GeneralSecurityException e)
    {
      keyStore = KeyStore.getInstance(type);
    }
    keyStore.load(ins, pin);
    PrivateKey key = (PrivateKey)keyStore.getKey(alias, keyPin);
    Certificate[] origChain = keyStore.getCertificateChain(alias);
    X509Certificate[] chain = null;
    if (key == null && origChain == null)
    {
      StringBuilder builder = new StringBuilder(50);
      builder.append("Wrong alias ").append(alias).append(", available are ");
      for ( Enumeration<String> aliases = keyStore.aliases() ; aliases.hasMoreElements() ; )
      {
        builder.append('"').append(aliases.nextElement()).append("\", ");
      }
      throw new IOException(builder.toString());
    }
    else if (origChain != null)
    {
      chain = Arrays.copyOf(origChain, origChain.length, X509Certificate[].class);
    }
    return new X509KeyPair(key, chain);
  }

  /**
   * Read a key and certificate form a given input stream. When reading a pem file it does only work for pem files
   * containing not more than one certificate and one private key. Providing more causes unpredictable behavior. Pem
   * file containing only a private key or only a certificate are also supported. Reading of pem files is not supported
   * with java 1.5 (also, java 1.5 needs endorsed xerces!)
   *
   * @param ins stream to read the keystore or PEM from
   * @param type keystore type, i.e. "PKCS12", "JKS" or "PEM"
   * @param pin keystore password
   * @param alias alias of the requested key pair. If a wrong value is given, look at stderr to see the available
   *          aliases. The alias parameter is not supported for pem files.
   * @param keyPin key password
   * @param strict <code>true</code> for checking key size
   */
  public static X509KeyPair readKeyAndCert(InputStream ins,
                                           String type,
                                           char[] pin,
                                           String alias,
                                           char[] keyPin,
                                           boolean strict)
    throws IOException, GeneralSecurityException, ErrorCodeException
  {
    X509KeyPair kp = readKeyAndCert(ins, type, pin, alias, keyPin);
    if (strict)
    {
      for ( X509Certificate c : kp.getChain() )
      {
        ensureKeySize(c);
      }
    }
    return kp;
  }

  /**
   * Read a certificate form a given input stream. Reading of pem files is not supported with java 1.5 (also, java 1.5
   * needs endorsed xerces!)
   *
   * @param ins stream to read the keystore or pem from
   * @param type for normal certificate the type is "X509", when reading a certificate from pem file use "PEM" as type.
   *          This will also return an X509 certificate.
   * @throws CertificateException
   */
  public static Certificate readCert(InputStream ins, String type) throws CertificateException
  {
    if (ins == null)
    {
      throw new NullPointerException("input stream to load key and cert from cannot be null");
    }
    CertificateFactory certFactory = CertificateFactory.getInstance(type, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    Certificate cert = certFactory.generateCertificate(ins);
    if (cert == null)
    {
      throw new CertificateException("Could not parse certificate");
    }
    return cert;
  }

  /**
   * Read a certificate form a given input stream.
   *
   * @param ins stream to read the keystore from
   * @throws CertificateException
   */
  public static X509Certificate readCert(InputStream ins) throws CertificateException
  {
    return (X509Certificate)readCert(ins, "X509");
  }

  /**
   * Converts the given certificate to a certificate from the Sun provider. Some application need the certificates to
   * come from the sun certificate provider and do not work correctly with BC certificates.
   *
   * @param cert
   * @return
   * @throws CertificateException
   * @throws NoSuchProviderException
   */
  public static <T extends Certificate> T convertToSun(T cert) throws CertificateException, NoSuchProviderException
  {
    if (cert == null)
    {
      return null;
    }
    CertificateFactory certFactory = CertificateFactory.getInstance(cert.getType(), "SUN");
    return (T)certFactory.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
  }

  /**
   * Read an X509 certificate form a given byte array.
   *
   * @param data serialized certificate (ber-encoded X509)
   * @throws CertificateException
   */
  public static X509Certificate readCert(byte[] data) throws CertificateException
  {
    return data == null ? null : (X509Certificate)readCert(new ByteArrayInputStream(data), "X509");
  }

  /**
   * @param stream
   * @param password
   * @return
   * @throws UnrecoverableKeyException
   * @throws KeyStoreException
   * @throws NoSuchAlgorithmException
   * @throws CertificateException
   * @throws IOException
   * @throws NoSuchProviderException
   */
  public static X509KeyPair readPKCS12(InputStream stream, char[] password) throws UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException
  {
    return readPKCS12(stream, password, null);
  }

  /**
   * @param stream
   * @param password
   * @param alias
   * @return
   * @throws KeyStoreException
   * @throws NoSuchAlgorithmException
   * @throws CertificateException
   * @throws IOException
   * @throws UnrecoverableKeyException
   */
  private static X509KeyPair readPKCS12(InputStream stream, char[] password, String alias)
    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException
  {
    KeyStore p12 = KeyStore.getInstance("pkcs12", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    p12.load(stream, password);
    Enumeration<String> e = p12.aliases();
    PrivateKey key = null;
    X509Certificate cert = null;
    StringBuilder aliasBuf = new StringBuilder();
    while (e.hasMoreElements())
    {
      String currentalias = e.nextElement();
      aliasBuf.append(currentalias);
      aliasBuf.append(" ||| ");
      cert = (X509Certificate)p12.getCertificate(currentalias);
      key = (PrivateKey)p12.getKey(currentalias, password);
      if (key != null && (isNullOrEmpty(alias) || currentalias.equals(alias)))
      {
        // take the first one
        break;
      }
    }
    if (key != null)
    {
      return new X509KeyPair(key, cert);
    }
    else
    {
      throw new KeyStoreException("keystore does not contains alias " + alias + ". Try alias " + aliasBuf.toString());
    }
  }

  /**
   * Checks if a given string is null or empty.
   *
   * @param s the string to be checked
   * @return true if the string is null or empty, false otherwise
   */
  public static boolean isNullOrEmpty(String s)
  {
    return s == null || s.isEmpty();
  }

  /**
   * Encodes a string to Base64
   *
   * @param s A String
   * @return String encoded in Base64
   */
  public static String toBase64(String s)
  {
    return new String(Base64.getEncoder().encode(s.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
  }

  /**
   * Decodes a string to Base64
   *
   * @param s A String encoded in Base64
   * @return A decoded String
   */
  public static String fromBase64(String s)
  {
    return new String(Base64.getDecoder().decode(s.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
  }

  /**
   * Return URL prefix from http request.
   */
  public static String createOwnUrlPrefix(HttpServletRequest req)
  {
    return req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort();
  }

  /**
   * Returns an HTML page for an error case.
   */
  public static String createErrorMessage(String errorMessage)
  {
    return HTML_ERROR.replace("${MESSAGE}", errorMessage);
  }

  /**
   * Read an X509 certificate form a given byte array.
   *
   * @param data serialized certificate (ber-encoded X509)
   * @param strict <code>true</code> for checking minimum key size
   * @throws CertificateException
   */
  public static X509Certificate readCert(byte[] data, boolean strict) throws CertificateException, ErrorCodeException
  {
    X509Certificate cert = readCert(data);
    if (strict)
    {
      ensureKeySize(cert);
    }
    return cert;
  }

  public static void ensureKeySize(X509Certificate cert) throws ErrorCodeException
  {
    if (cert == null)
    {
      return;
    }

    switch (cert.getPublicKey().getAlgorithm())
    {
      case "RSA":
        if (((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() < MIN_KEY_SIZE_RSA_SAML)
        {
          String message = String.format("Certificate with subject %s and serial %s does not meet specified minimum RSA key size of %d",
                                         cert.getSubjectX500Principal(),
                                         cert.getSerialNumber(),
                                         MIN_KEY_SIZE_RSA_SAML);
          log.warn(message);
          throw new ErrorCodeException(ErrorCode.INVALID_CERTIFICATE, message);
        }
        break;
      case "EC":
        ECParameterSpec ecKeyParams = ((ECPublicKey)cert.getPublicKey()).getParams();
        if (!(ecKeyParams instanceof ECNamedCurveSpec || ecKeyParams instanceof sun.security.util.NamedCurve))
        {
          String message = String.format("Certificate with subject %s and serial %s does not use a named curve",
                                         cert.getSubjectX500Principal(),
                                         cert.getSerialNumber());
          log.warn(message);
          throw new ErrorCodeException(ErrorCode.INVALID_CERTIFICATE, message);
        }
        if (ecKeyParams.getCurve().getField().getFieldSize() < MIN_KEY_SIZE_EC_SAML)
        {
          String message = String.format("Certificate with subject %s and serial %s does not meet specified minimum EC key size of %d",
                                         cert.getSubjectX500Principal(),
                                         cert.getSerialNumber(),
                                         MIN_KEY_SIZE_EC_SAML);
          log.warn(message);
          throw new ErrorCodeException(ErrorCode.INVALID_CERTIFICATE, message);
        }
        break;
      default:
    }
  }

  /**
   * Removes "file:" from the input if present. This can be used to use SPRING_CONFIG_LOCATION or spring.config.location
   * to specify config locations.
   *
   * @param location the string containing the value of SPRING_CONFIG_LOCATION or spring.config.location. Must not be
   *          null.
   * @return the input string without "file:" if it was present
   */
  public static String prepareSpringConfigLocation(String location)
  {
    if (location.startsWith("file:"))
    {
      return location.substring(5, location.length());
    }
    return location;
  }

  /**
   * Returns an initialized {@link BasicParserPool} ready to use, configured with security features preventing several
   * XXE attacks.
   *
   * @return the parser pool
   * @throws ComponentInitializationException
   */
  public static BasicParserPool getBasicParserPool() throws ComponentInitializationException
  {
    BasicParserPool ppMgr = new BasicParserPool();
    ppMgr.setNamespaceAware(true);

    final HashMap<String, Boolean> features = new HashMap<>();
    features.put(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    features.put(DISALLOW_DOCTYPE_DECL, true);
    features.put(EXTERNAL_GENERAL_ENTITIES, false);
    features.put("http://xml.org/sax/features/external-parameter-entities", false);
    features.put("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    ppMgr.setBuilderFeatures(features);
    ppMgr.setXincludeAware(false);
    ppMgr.setExpandEntityReferences(false);

    ppMgr.initialize();
    return ppMgr;
  }

  /**
   * Returns an initialized {@link DocumentBuilder} ready to use, configured with security features preventing several
   * XXE attacks.
   *
   * @return the document builder
   * @throws ParserConfigurationException
   */
  public static DocumentBuilder getDocumentBuilder() throws ParserConfigurationException
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    dbf.setFeature(DISALLOW_DOCTYPE_DECL, true);
    dbf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    dbf.setNamespaceAware(true);
    return dbf.newDocumentBuilder();
  }

  /**
   * Returns an initialized {@link Transformer} ready to use, configured with security features preventing several XXE
   * attacks.
   *
   * @return the transformer
   * @throws TransformerConfigurationException
   */
  public static Transformer getTransformer() throws TransformerConfigurationException
  {
    TransformerFactory tf = TransformerFactory.newInstance();
    tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    return tf.newTransformer();
  }

  /**
   * Returns an initialized {@link SchemaFactory} ready to use, configured with security features preventing several XXE
   * attacks.
   *
   * @return the schema factory
   * @throws SAXNotRecognizedException
   * @throws SAXNotSupportedException
   */
  public static SchemaFactory getSchemaFactory() throws SAXNotRecognizedException, SAXNotSupportedException
  {
    SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    return sf;
  }

  /**
   * Returns an initialized {@link Validator} ready to use, configured with security features preventing several XXE
   * attacks.
   *
   * @return the validator
   * @throws SAXNotRecognizedException
   * @throws SAXNotSupportedException
   */
  public static Validator getValidator(Schema schema) throws SAXNotRecognizedException, SAXNotSupportedException
  {
    Validator v = schema.newValidator();
    v.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    v.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    return v;
  }

  /**
   * Returns an initialized {@link SAXParserFactory} ready to use, configured with security features preventing several
   * XXE attacks.
   *
   * @return the parser factory
   * @throws SAXNotRecognizedException
   * @throws SAXNotSupportedException
   * @throws ParserConfigurationException
   */
  public static SAXParserFactory getSAXParserFactory()
    throws SAXNotRecognizedException, SAXNotSupportedException, ParserConfigurationException
  {
    SAXParserFactory spf = SAXParserFactory.newInstance();
    spf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
    spf.setFeature(DISALLOW_DOCTYPE_DECL, true);
    return spf;
  }
}
