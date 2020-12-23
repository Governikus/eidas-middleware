/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
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
import java.security.Security;
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

import javax.xml.namespace.QName;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.core.impl.RequesterIDBuilder;
import org.opensaml.saml.saml2.core.impl.ScopingBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;

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
import se.litsec.eidas.opensaml.common.EidasLoaEnum;


class TestEidasSaml
{

  private static final String EIDAS_EXTENSION_NAMESPACE_URI = "http://eidas.europa.eu/saml-extensions";

  private static final String EIDAS = "eidas";

  private static final String NAME = "Name";

  private static final String NAME_FORMAT = "NameFormat";

  // *.p12 used for tests.
  private static final String TEST_P12 = "/eidassignertest.p12";

  @BeforeEach
  void setUp() throws Exception
  {
    EidasSaml.init();
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void createParseRequest() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException,
    NoSuchAlgorithmException, NoSuchProviderException, XMLParserException, UnmarshallingException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException, ErrorCodeException,
    InitializationException, ComponentInitializationException
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
    EidasNameIdType nameIdPolicy = EidasNameIdType.PERSISTENT;
    EidasLoaEnum loa = EidasLoaEnum.LOA_LOW;
    List<X509Certificate> authors = new ArrayList<>();

    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    authors.add(cert);
    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12), "123456".toCharArray())
                         .getKey();
    EidasSigner signer = new EidasSigner(pk, cert);

    AuthnRequest authnRequest = buildAuthnRequest(requestedAttributes);

    byte[] request = EidasSaml.createRequest(issuer,
                                             destination,
                                             providerName,
                                             null,
                                             signer,
                                             requestedAttributes,
                                             null,
                                             nameIdPolicy,
                                             loa);
    String resultStr = new String(org.bouncycastle.util.encoders.Base64.encode(request), StandardCharsets.UTF_8);
    System.out.println("--->" + resultStr);
    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    AuthnRequest createdRequest = result.getAuthnRequest();
    assertEquals(issuer, result.getIssuer());
    assertEquals(destination, result.getDestination());
    assertEquals(providerName, result.getProviderName());
    assertEquals(destination, result.getDestination());
    assertEquals(loa, result.getAuthClassRef());
    assertEquals(authnRequest.isForceAuthn(), createdRequest.isForceAuthn());
    assertEquals(authnRequest.isPassive(), createdRequest.isPassive());
    assertEquals(requestedAttributes.size(), result.getRequestedAttributesEntries().size());
    assertNull(createdRequest.getScoping());
    assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().size(),
                 createdRequest.getExtensions().getUnknownXMLObjects().size());
    assertEquals(authnRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size(),
                 createdRequest.getExtensions().getUnknownXMLObjects().get(0).getOrderedChildren().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributesEntries() )
    {
      assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  void requestFromXMLfile() throws IOException, CertificateException, XMLParserException, UnmarshallingException,
    ErrorCodeException, InitializationException, ComponentInitializationException
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
    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    List<X509Certificate> authors = new ArrayList<>();
    authors.add(cert);


    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequest_13062017.xml"));


    EidasRequest result = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);
    assertEquals(issuer, result.getIssuer());
    assertEquals(destination, result.getDestination());
    assertEquals(providerName, result.getProviderName());
    assertEquals(destination, result.getDestination());
    assertEquals(requestedAttributes.size(), result.getRequestedAttributesEntries().size());
    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : result.getRequestedAttributesEntries() )
    {
      assertEquals(requestedAttributes.get(entry.getKey()), entry.getValue());
    }
  }

  @Test
  void createParseResponse() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException,
    NoSuchAlgorithmException, NoSuchProviderException, KeyException, XMLParserException, UnmarshallingException,
    EncryptionException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ErrorCodeException, InitializationException, ComponentInitializationException
  {
    BirthNameAttribute birthName = new BirthNameAttribute("Meyer");
    CurrentAddressAttribute currentAddress = new CurrentAddressAttribute("Am Fallturm", "33", "Bremen", "28207", "100",
                                                                         "bla", "bla", "bla", "bla");
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
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
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

    assertEquals(destination, result.getDestination());
    assertEquals(nameid.getValue(), result.getNameId().getValue());
    assertEquals(issuer, result.getIssuer());
    assertEquals(inResponseTo, result.getInResponseTo());
    for ( int i = 0 ; i < att.size() ; i++ )
    {
      assertEquals(att.get(i), result.getAttributes().get(i));
    }
  }

  @Test
  void createParseErrorResponse() throws CertificateException, IOException, UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, KeyException, XMLParserException,
    UnmarshallingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException, ErrorCodeException, ComponentInitializationException
  {
    String destination = "test destination";
    String recipient = "test_recipient";
    EidasNameId nameid = new EidasPersistentNameId("eidasnameidTest");
    String issuer = "test issuer";
    String inResponseTo = "test inResponseTo";
    EidasLoaEnum loa = EidasLoaEnum.LOA_SUBSTANTIAL;
    X509Certificate[] cert = {Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
    X509KeyPair[] keypair = {Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12),
                                              "123456".toCharArray())};
    PrivateKey pk = keypair[0].getKey();
    EidasEncrypter encrypter = new EidasEncrypter(true, cert[0]);
    EidasSigner signer = new EidasSigner(true, pk, cert[0]);

    byte[] response = new EidasResponse(destination, recipient, nameid, inResponseTo, issuer, loa, signer,
                                        encrypter).generateErrorRsp(ErrorCode.AUTHORIZATION_FAILED, "Cancel!");

    EidasResponse result = EidasResponse.parse(new ByteArrayInputStream(response), keypair, cert);

    assertEquals(destination, result.getDestination());
    assertEquals(StatusCode.AUTHN_FAILED,
                 result.getOpenSamlResponse().getStatus().getStatusCode().getStatusCode().getValue());
    assertEquals(issuer, result.getIssuer());
    assertEquals(inResponseTo, result.getInResponseTo());
  }

  @Test
  void createParseMetaDataService() throws IOException, XMLParserException, UnmarshallingException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException,
    CertificateException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
    NoSuchProviderException, ParseException, InitializationException, ComponentInitializationException
  {
    String id = "test id";
    String entityId = "test entityid";
    String middlewareVersion = "1.2";
    Date validUntil = new SimpleDateFormat("dd.MM.yyyy").parse("01.01.2025");

    X509Certificate sigCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    X509Certificate encCert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    EidasOrganisation organisation = new EidasOrganisation("eidas orga", "EIDAS LLC", "http://www.example.com", "en");
    EidasContactPerson technicalcontact = new EidasContactPerson("technical company", "Michelle", "Obama", "0123456789",
                                                                 "technical@example.com", "technical");
    EidasContactPerson supportContact = new EidasContactPerson("support  company", "Barack", "Obama", "789",
                                                               "support@example.com", "support");
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

    PrivateKey pk = Utils.readPKCS12(TestEidasSaml.class.getResourceAsStream(TEST_P12), "123456".toCharArray())
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
                                                 signer,
                                                 middlewareVersion,
                                                 true,
                                                 true);
    EidasMetadataService emds = EidasSaml.parseMetaDataService(new ByteArrayInputStream(mds));
    assertEquals(encCert, emds.getEncCert());
    assertEquals(entityId, emds.getEntityId());
    assertEquals(id, emds.getId());
    assertEquals(middlewareVersion, emds.getMiddlewareVersion());
    assertEquals(organisation.getName(), emds.getOrganisation().getName());
    assertEquals(organisation.getDisplayName(), emds.getOrganisation().getDisplayName());
    assertEquals(organisation.getLangId(), emds.getOrganisation().getLangId());
    assertEquals(organisation.getUrl(), emds.getOrganisation().getUrl());
    assertEquals(postEndpoint, emds.getPostEndpoint());
    assertEquals(redirectEndpoint, emds.getRedirectEndpoint());
    assertEquals(sigCert, emds.getSigCert());
    assertEquals(supportContact.getCompany(), emds.getSupportContact().getCompany());
    assertEquals(supportContact.getEmail(), emds.getSupportContact().getEmail());
    assertEquals(supportContact.getGivenName(), emds.getSupportContact().getGivenName());
    assertEquals(supportContact.getSurName(), emds.getSupportContact().getSurName());
    assertEquals(supportContact.getTel(), emds.getSupportContact().getTel());
    assertEquals(supportContact.getType(), emds.getSupportContact().getType());
    assertEquals(technicalcontact.getCompany(), emds.getTechnicalContact().getCompany());
    assertEquals(technicalcontact.getEmail(), emds.getTechnicalContact().getEmail());
    assertEquals(technicalcontact.getGivenName(), emds.getTechnicalContact().getGivenName());
    assertEquals(technicalcontact.getSurName(), emds.getTechnicalContact().getSurName());
    assertEquals(technicalcontact.getTel(), emds.getTechnicalContact().getTel());
    assertEquals(technicalcontact.getType(), emds.getTechnicalContact().getType());
    assertEquals(validUntil, emds.getValidUntil());
    assertEquals(attributes.size(), emds.getAttributes().size());
  }

  private AuthnRequest buildAuthnRequest(Map<EidasPersonAttributes, Boolean> requestedAttributes)
  {
    AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
    authnRequest.setDestination("destination");
    authnRequest.setIsPassive(false);
    authnRequest.setForceAuthn(true);
    setRequesterId(authnRequest);
    setExtension(authnRequest, requestedAttributes);

    return authnRequest;
  }

  private void setExtension(AuthnRequest authnRequest, Map<EidasPersonAttributes, Boolean> requestedAttributes)
  {
    Extensions extensions = new ExtensionsBuilder().buildObject();
    XSAny requestedAttributeExtension = new XSAnyBuilder().buildObject(EIDAS_EXTENSION_NAMESPACE_URI,
                                                                       "RequestedAttributes",
                                                                       EIDAS);

    for ( Map.Entry<EidasPersonAttributes, Boolean> entry : requestedAttributes.entrySet() )
    {
      XSAny requestedAttribute = new XSAnyBuilder().buildObject(EIDAS_EXTENSION_NAMESPACE_URI,
                                                                "RequestedAttribute",
                                                                EIDAS);
      requestedAttribute.getUnknownAttributes().put(new QName(NAME), entry.getKey().getName());
      requestedAttribute.getUnknownAttributes()
                        .put(new QName(NAME_FORMAT), "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
      requestedAttribute.getUnknownAttributes().put(new QName("isRequired"), entry.getValue().toString());
      requestedAttributeExtension.getUnknownXMLObjects().add(requestedAttribute);

    }
    extensions.getUnknownXMLObjects().add(requestedAttributeExtension);
    authnRequest.setExtensions(extensions);
  }

  private void setRequesterId(AuthnRequest authnRequest)
  {
    Scoping scoping = new ScopingBuilder().buildObject();
    RequesterID requesterID = new RequesterIDBuilder().buildObject();
    requesterID.setRequesterID("test requesterId");
    scoping.getRequesterIDs().add(requesterID);
    authnRequest.setScoping(scoping);
  }
}
