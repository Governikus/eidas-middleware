package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.CredentialSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.SAML2IntSecurityConfiguration;
import se.swedenconnect.opensaml.xmlsec.encryption.support.DecryptionUtils;


class EidasEncrypterTest
{

  public static final String RSA_KEYSTORE = "/eidassignertest.p12";

  public static final String EC_KEYSTORE = "/eidassignertest_ec.p12";

  @BeforeEach
  void setUp() throws Exception
  {
    OpenSAMLInitializer.getInstance()
                       .initialize(new OpenSAMLSecurityDefaultsConfig(new SAML2IntSecurityConfiguration()),
                                   new OpenSAMLSecurityExtensionConfig());
  }


  @Test
  void testEncryptionWithECCertificate() throws Exception
  {
    List<EidasAttribute> att = getEidasAttributes();
    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "test inResponseTo";
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
    Utils.X509KeyPair[] keypair = {Utils.readPKCS12(EidasEncrypterTest.class.getResourceAsStream(EC_KEYSTORE),
                                                    "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    X509Certificate cert = keypair[0].getCert();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert);
    Assertions.assertNotNull(encrypter.encrypter);
    EidasSigner signer = new EidasSigner(true, pk, cert);

    byte[] response = EidasSaml.createResponse(att,
                                               destination,
                                               recipient,
                                               nameid,
                                               issuer,
                                               loa,
                                               inResponseTo,
                                               encrypter,
                                               signer);

    Response samlResponse = getSamlResponse(response);

    Assertions.assertEquals(1, samlResponse.getEncryptedAssertions().size());

    Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(CredentialSupport.getSimpleCredential(cert,
                                                                                                                         pk)));

    Assertion assertion = decrypter.decrypt(samlResponse.getEncryptedAssertions().get(0));
    List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
    Assertions.assertEquals(att.size(), attributeStatements.get(0).getAttributes().size());
  }

  @Test
  void testEncryptionWithRSACertificate() throws Exception
  {
    List<EidasAttribute> att = getEidasAttributes();
    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "test inResponseTo";
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
    Utils.X509KeyPair[] keypair = {Utils.readPKCS12(EidasEncrypterTest.class.getResourceAsStream(RSA_KEYSTORE),
                                                    "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    X509Certificate cert = keypair[0].getCert();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert);
    Assertions.assertNotNull(encrypter.encrypter);
    EidasSigner signer = new EidasSigner(true, pk, cert);

    byte[] response = EidasSaml.createResponse(att,
                                               destination,
                                               recipient,
                                               nameid,
                                               issuer,
                                               loa,
                                               inResponseTo,
                                               encrypter,
                                               signer);

    Response samlResponse = getSamlResponse(response);

    Assertions.assertEquals(1, samlResponse.getEncryptedAssertions().size());

    Decrypter decrypter = new Decrypter(DecryptionUtils.createDecryptionParameters(CredentialSupport.getSimpleCredential(cert,
                                                                                                                         pk)));

    Assertion assertion = decrypter.decrypt(samlResponse.getEncryptedAssertions().get(0));
    List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
    Assertions.assertEquals(att.size(), attributeStatements.get(0).getAttributes().size());
  }

  private List<EidasAttribute> getEidasAttributes()
  {
    BirthNameAttribute birthName = new BirthNameAttribute("Meyer");
    CurrentAddressAttribute currentAddress = new CurrentAddressAttribute("bla", "bla", "bla", "bla", "Am Fallturm 33",
                                                                         "Bremen", "D", "HB", "28207");
    DateOfBirthAttribute dao = new DateOfBirthAttribute("1982-02-11");
    FamilyNameAttribute familyName = new FamilyNameAttribute("Müller");
    GivenNameAttribute givenName = new GivenNameAttribute("Björn");
    PersonIdentifierAttribute pi = new PersonIdentifierAttribute("test12321");
    PlaceOfBirthAttribute pob = new PlaceOfBirthAttribute("Saint-Étienne, France");
    ArrayList<EidasAttribute> att = new ArrayList<>();
    att.add(birthName);
    att.add(currentAddress);
    att.add(dao);
    att.add(familyName);
    att.add(givenName);
    att.add(pi);
    att.add(pob);
    return att;
  }

  private Response getSamlResponse(byte[] response)
    throws ComponentInitializationException, XMLParserException, UnmarshallingException
  {
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(new ByteArrayInputStream(response));
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    // Get apropriate unmarshaller
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    return (Response)unmarshaller.unmarshall(metadataRoot);
  }
}
