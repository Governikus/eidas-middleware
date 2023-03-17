/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.io.ByteStreams;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;


class EidasMetadataServiceTest
{

  private X509KeyPair keyPair;

  @BeforeEach
  void setUp() throws Exception
  {
    EidasSaml.init();
    keyPair = Utils.readPKCS12(EidasMetadataServiceTest.class.getResourceAsStream("/eidassignertest.p12"),
                               "123456".toCharArray());
  }

  @Test
  void createMetadataWithApplicationIdentifier() throws Exception
  {
    EidasMetadataService metadataService = getEidasMetadataService();
    EidasSigner signer = new EidasSigner(keyPair.getKey(), keyPair.getCert());

    byte[] metadataByteArray = metadataService.generate(signer);
    String metadataString = new String(metadataByteArray, StandardCharsets.UTF_8);
    Assertions.assertTrue(metadataString.contains("http://eidas.europa.eu/entity-attributes/application-identifier"));
    Assertions.assertTrue(metadataString.contains("German eIDAS Middleware version: 2.0"));
    Assertions.assertTrue(metadataString.contains("http://eidas.europa.eu/entity-attributes/protocol-version"));
  }

  @Test
  void validateMetadataWithWrongCredentialsThrowsSignatureException() throws Exception
  {
    EidasMetadataService eidasMetadataService = getEidasMetadataService();
    EidasSigner signer = new EidasSigner(keyPair.getKey(), keyPair.getCert());
    byte[] metadataByteArray = eidasMetadataService.generate(signer);
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataByteArray);
    SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    samlSignatureProfileValidator.validate(entityDescriptor.getSignature());
    X509Certificate x509Certificate = Utils.readCert(EidasMetadataServiceTest.class.getResourceAsStream("/WrongSignerCert.cer"));
    Signature sig = entityDescriptor.getSignature();
    BasicCredential bc = new BasicX509Credential(x509Certificate);
    Assertions.assertThrows(SignatureException.class, () -> SignatureValidator.validate(sig, bc));
  }

  @Test
  void validateUnsignedMetadataThrowsSignatureException() throws Exception
  {
    EidasMetadataService eidasMetadataService = getEidasMetadataService(false);
    EidasSigner signer = new EidasSigner(keyPair.getKey(), keyPair.getCert());
    byte[] metadataByteArray = eidasMetadataService.generate(signer);
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataByteArray);
    Signature sig = entityDescriptor.getSignature();
    Credential credential = new BasicX509Credential(keyPair.getCert());
    Assertions.assertThrows(ConstraintViolationException.class,
                            () -> SignatureValidator.validate(sig, credential));
  }

  @Test
  void manipulatedMetadataThrowsSignatureException() throws Exception
  {
    EidasMetadataService eidasMetadataService = getEidasMetadataService();
    EidasSigner signer = new EidasSigner(keyPair.getKey(), keyPair.getCert());
    byte[] metadataByteArray = eidasMetadataService.generate(signer);
    String metadataString = new String(metadataByteArray);
    String manipulatedString = metadataString.replace("entityID", "newEntityID");
    byte[] manipulatedStringBytes = manipulatedString.getBytes(StandardCharsets.UTF_8);
    EntityDescriptor entityDescriptor = getEntityDescriptor(manipulatedStringBytes);
    SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    samlSignatureProfileValidator.validate(entityDescriptor.getSignature());
    Credential credential = new BasicX509Credential(keyPair.getCert());
    Signature sig = entityDescriptor.getSignature();
    Assertions.assertThrows(SignatureException.class, () -> SignatureValidator.validate(sig, credential));
  }

  @Test
  void validateMetadataSignature() throws Exception
  {
    EidasMetadataService metadataService = getEidasMetadataService();
    EidasSigner signer = new EidasSigner(keyPair.getKey(), keyPair.getCert());
    byte[] metadataByteArray = metadataService.generate(signer);
    EntityDescriptor metadata = getEntityDescriptor(metadataByteArray);
    SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    samlSignatureProfileValidator.validate(metadata.getSignature());
    Credential credential = new BasicX509Credential(keyPair.getCert());
    SignatureValidator.validate(metadata.getSignature(), credential);
  }

  @Test
  void validateMetadataFileSignature() throws Exception
  {
    InputStream resourceAsStream = EidasMetadataServiceTest.class.getResourceAsStream("/Metadata.xml");
    byte[] metadataByteArray = ByteStreams.toByteArray(resourceAsStream);
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataByteArray);
    SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    samlSignatureProfileValidator.validate(entityDescriptor.getSignature());
    X509Certificate x509Certificate = Utils.readCert(EidasMetadataServiceTest.class.getResourceAsStream("/middleware_sign_crypt.cer"));
    Credential credential1 = new BasicX509Credential(x509Certificate);
    SignatureValidator.validate(entityDescriptor.getSignature(), credential1);
  }

  private EntityDescriptor getEntityDescriptor(byte[] metadataByteArray) throws Exception
  {
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(new ByteArrayInputStream(metadataByteArray));
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    return (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);
  }

  private EidasMetadataService getEidasMetadataService()
  {
    return getEidasMetadataService(true);
  }

  private EidasMetadataService getEidasMetadataService(boolean signed)
  {
    EidasOrganisation organisation = new EidasOrganisation("Gov", "Gov", "http://localhost", "de");
    EidasContactPerson contactPerson = new EidasContactPerson("Gov", "hans", "meyer", "0150", "test@test.de");
    ArrayList<EidasPersonAttributes> attributes = new ArrayList<>();
    attributes.add(EidasNaturalPersonAttributes.FAMILY_NAME);
    attributes.add(EidasNaturalPersonAttributes.FIRST_NAME);
    attributes.add(EidasNaturalPersonAttributes.CURRENT_ADDRESS);
    attributes.add(EidasNaturalPersonAttributes.PERSON_IDENTIFIER);
    attributes.add(EidasNaturalPersonAttributes.BIRTH_NAME);
    attributes.add(EidasNaturalPersonAttributes.PLACE_OF_BIRTH);
    attributes.add(EidasNaturalPersonAttributes.DATE_OF_BIRTH);

    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.PERSISTENT);
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    return new EidasMetadataService("id", "entityID", Instant.now(), keyPair.getCert(), keyPair.getCert(),
                                    organisation, contactPerson, contactPerson, "https://post-endpoint.com",
                                    "https://redirect-endpoint.com", attributes, supportedNameIdTypes, "2.0",
                                    signed, true, "DE");
  }
}
