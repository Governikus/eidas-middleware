/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderType;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


public class TestEidasSaml
{

  // *.p12 used for tests.
  static final String TEST_P12 = "/eidassignertest.p12";
  @Before
  public void setUp() throws Exception
  {
    EidasSaml.init();
  }

  @Test
  public void createParseRequest() throws CertificateException, IOException, UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, XMLParserException,
    UnmarshallingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ErrorCodeException, InitializationException, ComponentInitializationException
  {
    String issuer = "https://test/";
    String destination = "test destination";
    String providerName = "test providername";
    Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();
    requestedAttributes.put(EidasNaturalPersonAttributes.BIRTH_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.FAMILY_NAME, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.GENDER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_PERSON_IDENTIFIER, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_NAME, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_ADDRESS, true);
    requestedAttributes.put(EidasLegalPersonAttributes.VAT_REGISTRATION, true);
    requestedAttributes.put(EidasLegalPersonAttributes.TAX_REFERENCE, true);
    requestedAttributes.put(EidasLegalPersonAttributes.D2012_17_EU_IDENTIFIER, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEI, true);
    requestedAttributes.put(EidasLegalPersonAttributes.EORI, true);
    requestedAttributes.put(EidasLegalPersonAttributes.SEED, true);
    requestedAttributes.put(EidasLegalPersonAttributes.SIC, true);
    EidasRequestSectorType selectorType = EidasRequestSectorType.PUBLIC;
    EidasNameIdType nameIdPolicy = EidasNameIdType.PERSISTENT;
    EidasLoA loa = EidasLoA.LOW;
    List<X509Certificate> authors = new ArrayList<>();

    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    authors.add(cert);
    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                     "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, cert);

    byte[] request = EidasSaml.createRequest(issuer,
                                             destination,
                                             providerName,
                                             signer,
                                             requestedAttributes,
                                             selectorType,
                                             nameIdPolicy,
                                             loa);
    String resultStr = new String(org.bouncycastle.util.encoders.Base64.encode(request),
                                  StandardCharsets.UTF_8);
    System.out.println("--->" + resultStr);
    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    assertEquals(issuer, result.getIssuer());
    assertEquals(destination, result.getDestination());
    assertEquals(providerName, result.getProviderName());
    assertEquals(destination, result.getDestination());
    assertEquals(requestedAttributes.size(), result.getRequestedAttributes().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributes() )
    {
      assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  public void requestFromXMLfile() throws IOException, CertificateException, XMLParserException,
    UnmarshallingException, ErrorCodeException, InitializationException, ComponentInitializationException
  {
    String issuer = "https://test/";
    String destination = "test destination";
    String providerName = "test providername";
    Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();
    requestedAttributes.put(EidasNaturalPersonAttributes.BIRTH_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.FAMILY_NAME, false);
    requestedAttributes.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.GENDER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    requestedAttributes.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_PERSON_IDENTIFIER, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_NAME, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEGAL_ADDRESS, true);
    requestedAttributes.put(EidasLegalPersonAttributes.VAT_REGISTRATION, true);
    requestedAttributes.put(EidasLegalPersonAttributes.TAX_REFERENCE, true);
    requestedAttributes.put(EidasLegalPersonAttributes.D2012_17_EU_IDENTIFIER, true);
    requestedAttributes.put(EidasLegalPersonAttributes.LEI, true);
    requestedAttributes.put(EidasLegalPersonAttributes.EORI, true);
    requestedAttributes.put(EidasLegalPersonAttributes.SEED, true);
    requestedAttributes.put(EidasLegalPersonAttributes.SIC, true);
    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    List<X509Certificate> authors = new ArrayList<>();
    authors.add(cert);


    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequest_13062017.xml"));


    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    assertEquals(issuer, result.getIssuer());
    assertEquals(destination, result.getDestination());
    assertEquals(providerName, result.getProviderName());
    assertEquals(destination, result.getDestination());
    assertEquals(requestedAttributes.size(), result.getRequestedAttributes().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributes() )
    {
      assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  public void createParseResponse() throws SAXException, CertificateException, IOException,
    UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException,
    KeyException, XMLParserException, UnmarshallingException, EncryptionException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException, ErrorCodeException,
    InitializationException, ComponentInitializationException
  {
    BirthNameAttribute birthName = new BirthNameAttribute("Meyer");
    CurrentAddressAttribute currentAddress = new CurrentAddressAttribute("Am Fallturm", "33", "Bremen",
                                                                         "28207", "100", "bla", "bla", "bla",
                                                                         "bla");
    DateOfBirthAttribute dao = new DateOfBirthAttribute("1982-02-11");
    FamilyNameAttribute familyName = new FamilyNameAttribute("Muller", "Müller");
    GenderAttribute gender = new GenderAttribute(GenderType.MALE);
    GivenNameAttribute givenName = new GivenNameAttribute("Bjorn", "Bjørn");
    PersonIdentifierAttribute pi = new PersonIdentifierAttribute("test12321");
    PlaceOfBirthAttribute pob = new PlaceOfBirthAttribute("Saint-Étienne, France");
    ArrayList<EidasAttribute> att = new ArrayList<>();
    att.add(birthName);
    att.add(currentAddress);
    att.add(dao);
    att.add(familyName);
    att.add(gender);
    att.add(givenName);
    att.add(pi);
    att.add(pob);

    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "test inResponseTo";
    EidasLoA loa = EidasLoA.SUBSTANTIAL;
    X509Certificate[] cert = {Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
    X509KeyPair[] keypair = {Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                              "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert[0]);
    EidasSigner signer = new EidasSigner(true, pk, cert[0]);

    byte[] response = EidasSaml.createResponse(att,
                                               destination,
                                               recipient,
                                               nameid,
                                               issuer,
                                               loa,
                                               inResponseTo,
                                               encrypter,
                                               signer);
    System.out.println("-->>Response-->>" + new String(response));

    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(response), keypair, cert);

    assertEquals(result.getDestination(), destination);
    assertEquals(result.getNameId().getValue(), nameid.getValue());
    assertEquals(result.getIssuer(), issuer);
    assertEquals(result.getInResponseTo(), inResponseTo);
    for ( int i = 0 ; i < att.size() ; i++ )
    {
      assertEquals(result.getAttributes().get(i).getLatinScript().replaceAll("\\s+", ""),
                   att.get(i).getLatinScript().replaceAll("\\s+", ""));
    }

  }

  @Test
  public void createParseErrorResponse() throws SAXException, CertificateException, IOException,
    UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException,
    KeyException, XMLParserException, UnmarshallingException, EncryptionException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException, ErrorCodeException,
    InitializationException, ComponentInitializationException
  {
    BirthNameAttribute birthName = new BirthNameAttribute("Meyer");
    CurrentAddressAttribute currentAddress = new CurrentAddressAttribute("Am Fallturm", "33", "Bremen",
                                                                         "28207", "100", "bla", "bla", "bla",
                                                                         "bla");
    DateOfBirthAttribute dao = new DateOfBirthAttribute("1982-02-11");
    FamilyNameAttribute familyName = new FamilyNameAttribute("Muller", "Müller");
    GenderAttribute gender = new GenderAttribute(GenderType.MALE);
    GivenNameAttribute givenName = new GivenNameAttribute("Bjorn", "Bjørn");
    PersonIdentifierAttribute pi = new PersonIdentifierAttribute("test12321");
    PlaceOfBirthAttribute pob = new PlaceOfBirthAttribute("Saint-Étienne, France");
    ArrayList<EidasAttribute> att = new ArrayList<>();
    att.add(birthName);
    att.add(currentAddress);
    att.add(dao);
    att.add(familyName);
    att.add(gender);
    att.add(givenName);
    att.add(pi);
    att.add(pob);

    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "test inResponseTo";
    EidasLoA loa = EidasLoA.SUBSTANTIAL;
    X509Certificate[] cert = {Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
    X509KeyPair[] keypair = {Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                              "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert[0]);
    EidasSigner signer = new EidasSigner(true, pk, cert[0]);

    byte[] response = new EidasResponse(destination, recipient, nameid, inResponseTo, issuer, loa, signer,
                                        encrypter).generateErrorRsp(ErrorCode.AUTHORIZATION_FAILED,
                                                                    "Cancel!");

    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(response), keypair, cert);

    assertEquals(result.getDestination(), destination);
    assertNull(result.getNameId());
    assertEquals(result.getIssuer(), issuer);
    assertEquals(result.getInResponseTo(), inResponseTo);


  }


  @Test
  public void createParseMetaDataService() throws IOException, XMLParserException, UnmarshallingException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException,
    CertificateException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
    NoSuchProviderException, ParseException, InitializationException, ComponentInitializationException
  {
    String id = "test id";
    String entityId = "test entityid";
    Date validUntil = new SimpleDateFormat("dd.MM.yyyy").parse("01.01.2025");

    X509Certificate sigCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    X509Certificate encCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    EidasOrganisation organisation = new EidasOrganisation("eidas orga", "EIDAS LLC",
                                                           "http://www.example.com", "en");
    EidasContactPerson technicalcontact = new EidasContactPerson("technical company", "Michelle", "Obama",
                                                                 "0123456789", "technical@example.com",
                                                                 "technical");
    EidasContactPerson supportContact = new EidasContactPerson("support  company", "Barack", "Obama", "789",
                                                               "support@example.com", "support");
    ;
    String postEndpoint = "post.eu/endpoint";
    String redirectEndpoint = "redirect.eu/endpoint";
    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    List<EidasPersonAttributes> attributes = new ArrayList<>();
    attributes.add(EidasNaturalPersonAttributes.BIRTH_NAME);
    attributes.add(EidasNaturalPersonAttributes.CURRENT_ADDRESS);
    attributes.add(EidasNaturalPersonAttributes.DATE_OF_BIRTH);
    attributes.add(EidasNaturalPersonAttributes.FAMILY_NAME);
    attributes.add(EidasNaturalPersonAttributes.FIRST_NAME);
    attributes.add(EidasNaturalPersonAttributes.GENDER);
    attributes.add(EidasNaturalPersonAttributes.PERSON_IDENTIFIER);
    attributes.add(EidasNaturalPersonAttributes.PLACE_OF_BIRTH);

    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                     "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, sigCert);


    byte[] mds = EidasSaml.createMetaDataService(id,
                                                 entityId,
                                                 validUntil,
                                                 sigCert,
                                                 encCert,
                                                 organisation,
                                                 technicalcontact,
                                                 supportContact,
                                                 postEndpoint,
                                                 redirectEndpoint,
                                                 supportedNameIdTypes,
                                                 attributes,
                                                 signer);
    EidasMetadataService emds = EidasSaml.parseMetaDataService(new ByteArrayInputStream(mds));
    assertEquals(emds.getEncCert(), encCert);
    assertEquals(emds.getEntityId(), entityId);
    assertEquals(emds.getId(), id);
    assertEquals(emds.getOrganisation().getName(), organisation.getName());
    assertEquals(emds.getOrganisation().getDisplayName(), organisation.getDisplayName());
    assertEquals(emds.getOrganisation().getLangId(), organisation.getLangId());
    assertEquals(emds.getOrganisation().getUrl(), organisation.getUrl());
    assertEquals(emds.getPostEndpoint(), postEndpoint);
    assertEquals(emds.getRedirectEndpoint(), redirectEndpoint);
    assertEquals(emds.getSigCert(), sigCert);
    assertEquals(emds.getSupportcontact().getCompany(), supportContact.getCompany());
    assertEquals(emds.getSupportcontact().getEmail(), supportContact.getEmail());
    assertEquals(emds.getSupportcontact().getGivenName(), supportContact.getGivenName());
    assertEquals(emds.getSupportcontact().getSurName(), supportContact.getSurName());
    assertEquals(emds.getSupportcontact().getTel(), supportContact.getTel());
    assertEquals(emds.getSupportcontact().getType(), supportContact.getType());
    assertEquals(emds.getTechnicalContact().getCompany(), technicalcontact.getCompany());
    assertEquals(emds.getTechnicalContact().getEmail(), technicalcontact.getEmail());
    assertEquals(emds.getTechnicalContact().getGivenName(), technicalcontact.getGivenName());
    assertEquals(emds.getTechnicalContact().getSurName(), technicalcontact.getSurName());
    assertEquals(emds.getTechnicalContact().getTel(), technicalcontact.getTel());
    assertEquals(emds.getTechnicalContact().getType(), technicalcontact.getType());
    assertEquals(emds.getValidUntil(), validUntil);
    assertEquals(emds.getAttributes().size(), attributes.size());
  }
}
