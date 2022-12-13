package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.eidascommon.Utils;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;


class XMLSignatureHandlerTest
{

  private static final String TEST_P12_RSA = "/eidassignertest.p12";

  private static final String TEST_P12_EC = "/eidassignertest_ec.p12";

  private SignableXMLObject signableXMLObject;

  @BeforeEach
  void setUp() throws Exception
  {
    EidasSaml.init();
    signableXMLObject = getSignableXmlObject();
  }

  @ParameterizedTest
  @ValueSource(strings = {"SHB-256", "SHA-256-PSS", "SHA256-PSS", "SHA256PSS", "SHA-1", "SHA1"})
  void testWhenAddSignatureCalledWithUnknownDigestAlgoThenThrowIllegalArgumentException(String digestAlgo)
    throws Exception
  {
    X509Certificate cert = Utils.readCert(XMLSignatureHandlerTest.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    PrivateKey pk = Utils.readPKCS12(XMLSignatureHandlerTest.class.getResourceAsStream(TEST_P12_RSA),
                                     "123456".toCharArray())
                         .getKey();
    Assertions.assertThrows(IllegalArgumentException.class,
                            () -> XMLSignatureHandler.addSignature(signableXMLObject,
                                                                   pk,
                                                                   cert,
                                                                   XMLSignatureHandler.SigEntryType.CERTIFICATE,
                                                                   digestAlgo));
  }

  @Test
  void testWhenDigestAlgoNullThenThrowIllegalArgumentException() throws Exception
  {
    X509Certificate cert = Utils.readCert(XMLSignatureHandlerTest.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    PrivateKey pk = Utils.readPKCS12(XMLSignatureHandlerTest.class.getResourceAsStream(TEST_P12_RSA),
                                     "123456".toCharArray())
                         .getKey();
    Assertions.assertNull(signableXMLObject.getSignature());
    Assertions.assertThrows(IllegalArgumentException.class,
                            () -> XMLSignatureHandler.addSignature(signableXMLObject,
                                                                   pk,
                                                                   cert,
                                                                   XMLSignatureHandler.SigEntryType.CERTIFICATE,
                                                                   null));
  }

  @ParameterizedTest
  @ValueSource(strings = {"SHA-256", "SHA256", "SHA384", "SHA-384", "SHA512", "SHA-512"})
  void testWhenAddSignatureCalledWithRSAKeyAndKnownDigestAlgorithmThenAddSignature(String digestAlgo)
    throws Exception
  {
    X509Certificate cert = Utils.readCert(XMLSignatureHandlerTest.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    PrivateKey pk = Utils.readPKCS12(XMLSignatureHandlerTest.class.getResourceAsStream(TEST_P12_RSA),
                                     "123456".toCharArray())
                         .getKey();
    Assertions.assertNull(signableXMLObject.getSignature());
    XMLSignatureHandler.addSignature(signableXMLObject,
                                     pk,
                                     cert,
                                     XMLSignatureHandler.SigEntryType.CERTIFICATE,
                                     digestAlgo);
    Assertions.assertNotNull(signableXMLObject.getSignature());
  }

  @ParameterizedTest
  @ValueSource(strings = {"SHA-256", "SHA256", "SHA384", "SHA-384", "SHA512", "SHA-512"})
  void testWhenAddSignatureCalledWithECKeyAndKnownDigestAlgorithmThenAddSignature(String digestAlgo)
    throws Exception
  {
    X509Certificate cert = Utils.readCert(XMLSignatureHandlerTest.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    PrivateKey pk = Utils.readPKCS12(XMLSignatureHandlerTest.class.getResourceAsStream(TEST_P12_EC),
                                     "123456".toCharArray())
                         .getKey();
    Assertions.assertNull(signableXMLObject.getSignature());
    XMLSignatureHandler.addSignature(signableXMLObject,
                                     pk,
                                     cert,
                                     XMLSignatureHandler.SigEntryType.CERTIFICATE,
                                     digestAlgo);
    Assertions.assertNotNull(signableXMLObject.getSignature());
  }

  private SignableXMLObject getSignableXmlObject() throws Exception
  {
    try (
      InputStream resourceAsStream = EidasMetadataServiceTest.class.getResourceAsStream("/Metadata_without_signature.xml"))
    {
      byte[] metadataByteArray = ByteStreams.toByteArray(resourceAsStream);
      BasicParserPool ppMgr = Utils.getBasicParserPool();
      Document inCommonMDDoc = ppMgr.parse(new ByteArrayInputStream(metadataByteArray));
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      return (SignableXMLObject)unmarshaller.unmarshall(metadataRoot);
    }
  }
}
