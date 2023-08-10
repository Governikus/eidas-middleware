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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.xml.sax.SAXException;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;


/**
 * Put all method together for creating, validating and parsing of saml messages and make it easy. Using the
 * methods of this class will init opensaml automatically
 *
 * @author hohnholt
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EidasSaml
{

  private static boolean isInit = false;

  /**
   * Inits the OpenSAML library and the EidasSaml Starterkit library. It is necessary to call this method!
   */
  public static synchronized void init() throws InitializationException
  {
    if (!isInit)
    {
      try
      {
        OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityExtensionConfig());
        XMLObjectProviderRegistrySupport.deregisterObjectProvider(EidasNaturalPersonAttributes.DATE_OF_BIRTH.getQName());
      }
      catch (Exception e)
      {
        throw new InitializationException("EidasSaml: Can not init OpenSAML", e);
      }
      isInit = true;
    }
  }

  /**
   * Creates a signed eidas saml request
   *
   * @param issuer the name of the requester
   * @param destination the response destination
   * @param providerName the response provider
   * @param signer the author of the message
   * @param requestedAttributes a list of the requestAttributes
   * @param sectorType private sector or public sector SP
   * @param nameIdPolicy defines the treatment of identifiers to be used in a cross-border context
   * @param loa the Level of Assurance
   * @return signed saml xml request as byte array
   * @throws CertificateEncodingException thrown if the signer is not valid
   * @throws IOException there multiple reason why this can be thrown
   * @throws MarshallingException thrown if there is a problem to create the saml request
   * @throws SignatureException thrown if there is a problem to create the saml request (while signing)
   * @throws TransformerFactoryConfigurationError thrown if there is a problem to create the saml request
   * @throws TransformerException thrown if there is a problem to create the saml request
   * @throws InitializationException
   */
  public static byte[] createRequest(String issuer,
                                     String destination,
                                     String providerName,
                                     String requesterId,
                                     EidasSigner signer,
                                     Map<EidasPersonAttributes, Boolean> requestedAttributes,
                                     SPTypeEnumeration sectorType,
                                     EidasNameIdType nameIdPolicy,
                                     EidasLoaEnum loa)
    throws InitializationException, CertificateEncodingException, IOException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException
  {
    init();
    EidasRequest eidasRequest = new EidasRequest(destination, sectorType, nameIdPolicy, loa, issuer,
                                                 providerName, requesterId, signer);
    return eidasRequest.generate(requestedAttributes);
  }

  public static byte[] createRequest(String issuer,
                                     String destination,
                                     EidasSigner signer,
                                     Map<EidasPersonAttributes, Boolean> requestedAttributes,
                                     SPTypeEnumeration sectorType,
                                     EidasNameIdType nameIdPolicy,
                                     EidasLoaEnum loa)
    throws InitializationException, CertificateEncodingException, IOException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException
  {
    init();
    EidasRequest eidasRequest = new EidasRequest(destination, sectorType, nameIdPolicy, loa, issuer,
                                                 Constants.DEFAULT_PROVIDER_NAME, null, signer);
    return eidasRequest.generate(requestedAttributes);
  }

  /**
   * Generates an EidasRequest with a test case.
   *
   * @param issuer the issuer of the eIDAS-Request.
   * @param destination the destination of the eIDAS-Request.
   * @param signer the signer to sign the eIDAS-Request. Must not be null.
   * @param requestedAttributes the requested attributes for the eIDAS-Request.
   * @param sectorType the sector type of the eIDAS-Request.
   * @param nameIdPolicy the nameIdPolicy of theeIDAS-Request. Can be null. The default value is
   *          {@link EidasNameIdType#TRANSIENT}.
   * @param loa the level of assurance of the eIDAS-Request. Can be null. The defaul value is
   *          {@link EidasLoaEnum#LOA_HIGH}.
   * @param testCase the enum of the test case for the eIDAS-Request. Can be null.
   * @return the eIDAS-Request as a byte array.
   * @see EidasSaml#createRequest(String, String, EidasSigner, Map, SPTypeEnumeration, EidasNameIdType,
   *      EidasLoaEnum) create a request without a test case.
   **/
  public static byte[] createRequest(String issuer,
                                     String destination,
                                     EidasSigner signer,
                                     Map<EidasPersonAttributes, Boolean> requestedAttributes,
                                     SPTypeEnumeration sectorType,
                                     EidasNameIdType nameIdPolicy,
                                     EidasLoaEnum loa,
                                     TestCaseEnum testCase)
    throws InitializationException, CertificateEncodingException, IOException, MarshallingException,
    SignatureException, TransformerFactoryConfigurationError, TransformerException
  {
    init();
    EidasRequest eidasRequest = new EidasRequest(destination, sectorType, nameIdPolicy, loa, issuer,
                                                 Constants.DEFAULT_PROVIDER_NAME, null, signer, testCase);
    return eidasRequest.generate(requestedAttributes);
  }

  /**
   * Read a eidas saml request xml and creats a EidasRequest object
   *
   * @param is the eidas saml request
   * @return a representation of the eidas saml request
   * @throws XMLParserException thrown if there is a problem in the saml request xml
   * @throws UnmarshallingException thrown if there is a problem in the saml request xml
   * @throws ErrorCodeException thrown if there is a problem in the saml request xml
   * @throws InitializationException
   * @throws ComponentInitializationException
   */
  public static EidasRequest parseRequest(InputStream is) throws InitializationException, XMLParserException,
    UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    init();
    return EidasRequest.parse(is);
  }

  /**
   * Read a eidas saml request xml and checks the signatures
   *
   * @param is the eidas saml request
   * @param authors a list of author certificates to check the signaures
   * @return a representation of the eidas saml request
   * @throws XMLParserException thrown if there is a problem in the saml request xml
   * @throws UnmarshallingException thrown if there is a problem in the saml request xml
   * @throws ErrorCodeException thrown if there is a problem in the saml request xml
   * @throws InitializationException
   * @throws ComponentInitializationException
   */
  public static EidasRequest parseRequest(InputStream is, List<X509Certificate> authors)
    throws InitializationException, XMLParserException, UnmarshallingException, ErrorCodeException,
    ComponentInitializationException
  {
    init();
    return EidasRequest.parse(is, authors);
  }

  /**
   * Checks the signature of an already parsed request.
   *
   * @param request request to check
   * @param authors trusted signers
   * @throws InitializationException
   * @throws ErrorCodeException if signature is invalid or check cannot be performed
   */
  public static void verifyRequest(EidasRequest request, List<X509Certificate> authors)
    throws InitializationException, ErrorCodeException
  {
    init();
    EidasRequest.checkSignature(request.getAuthnRequest().getSignature(), authors);
  }

  /**
   * Creates a signed eidas saml response. the Assertion is encrypted
   *
   * @param att the values of the requested attributes
   * @param destination the response destination
   * @param recipient the response destination metadata URL
   * @param nameid defines the treatment of identifiers to be used in a cross-border context
   * @param issuer the name of the response sender
   * @param inResponseTo the responceTo id
   * @param encrypter the reader of the requested attributes
   * @param signer the author of this message
   * @return signed encrypted saml xml response as byte array
   * @throws CertificateEncodingException thrown if there any problems with the used certificates
   * @throws XMLParserException thrown if there any problem to create the message
   * @throws IOException there multiple reason why this can be thrown
   * @throws EncryptionException
   * @throws MarshallingException thrown if there any problem to create the message
   * @throws SignatureException
   * @throws TransformerFactoryConfigurationError thrown if there any problem to create the message
   * @throws TransformerException thrown if there any problem to create the message
   * @throws InitializationException
   */
  public static byte[] createResponse(List<EidasAttribute> att,
                                      String destination,
                                      String recipient,
                                      EidasNameId nameid,
                                      String issuer,
                                      EidasLoaEnum loa,
                                      String inResponseTo,
                                      EidasEncrypter encrypter,
                                      EidasSigner signer)
    throws InitializationException, CertificateEncodingException, XMLParserException, IOException,
    EncryptionException, MarshallingException, SignatureException, TransformerFactoryConfigurationError,
    TransformerException
  {
    init();
    EidasResponse response = new EidasResponse(att, destination, recipient, nameid, inResponseTo, issuer, loa,
                                               signer, encrypter);
    return response.generate();
  }

  /**
   * @param is
   * @param decryptionKeyPairs
   * @param signatureAuthors
   * @return
   * @throws InitializationException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws ErrorCodeException
   * @throws ComponentInitializationException
   */
  public static EidasResponse parseResponse(InputStream is,
                                            X509KeyPair[] decryptionKeyPairs,
                                            X509Certificate[] signatureAuthors)
    throws InitializationException, XMLParserException, UnmarshallingException, ErrorCodeException,
    ComponentInitializationException
  {
    init();
    return EidasResponse.parse(is, decryptionKeyPairs, signatureAuthors);
  }

  /**
   * @param id
   * @param entityId
   * @param validUntil
   * @param sigCert
   * @param encCert
   * @param organisation
   * @param technicalcontact
   * @param postEndpoint
   * @param redirectEndpoint
   * @param supportedNameIdTypes
   * @param attributes
   * @param signer
   * @param middlewareVersion
   * @param doSign
   * @param requesterIdFlag
   * @param nodeCountry
   * @return
   * @throws InitializationException
   * @throws CertificateEncodingException
   * @throws IOException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws TransformerFactoryConfigurationError
   * @throws TransformerException
   * @throws ComponentInitializationException
   */
  public static byte[] createMetaDataService(String id,
                                             String entityId,
                                             Instant validUntil,
                                             X509Certificate sigCert,
                                             X509Certificate encCert,
                                             EidasOrganisation organisation,
                                             EidasContactPerson technicalcontact,
                                             EidasContactPerson supportContact,
                                             String postEndpoint,
                                             String redirectEndpoint,
                                             List<EidasNameIdType> supportedNameIdTypes,
                                             List<EidasPersonAttributes> attributes,
                                             EidasSigner signer,
                                             String middlewareVersion,
                                             boolean doSign,
                                             boolean requesterIdFlag,
                                             String countryCode)
    throws CertificateEncodingException, IOException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException, InitializationException
  {
    init();
    EidasMetadataService meta = new EidasMetadataService(id, entityId, validUntil, sigCert, encCert,
                                                         organisation, technicalcontact, supportContact,
                                                         postEndpoint, redirectEndpoint, attributes,
                                                         supportedNameIdTypes, middlewareVersion, doSign,
                                                         requesterIdFlag, countryCode);
    return meta.generate(signer);
  }

  /**
   * @param is
   * @return
   * @throws InitializationException
   * @throws CertificateException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws IOException
   * @throws ComponentInitializationException
   */
  static EidasMetadataService parseMetaDataService(InputStream is) throws CertificateException,
    XMLParserException, UnmarshallingException, InitializationException, ComponentInitializationException
  {
    init();
    return EidasMetadataService.parse(is);
  }

  /**
   * @param id
   * @param entityId
   * @param validUntil
   * @param sigCert
   * @param encCert
   * @param organisation
   * @param postEndpoint
   * @param spType
   * @param supportedNameIdTypes
   * @param signer
   * @return
   * @throws CertificateEncodingException
   * @throws IOException
   * @throws MarshallingException
   * @throws SignatureException
   * @throws TransformerException
   * @throws InitializationException
   */
  public static byte[] createMetaDataNode(String id,
                                          String entityId,
                                          Instant validUntil,
                                          X509Certificate sigCert,
                                          X509Certificate encCert,
                                          EidasOrganisation organisation,
                                          EidasContactPerson techcontact,
                                          EidasContactPerson supportcontact,
                                          String postEndpoint,
                                          SPTypeEnumeration spType,
                                          List<EidasNameIdType> supportedNameIdTypes,
                                          EidasSigner signer)
    throws InitializationException, CertificateEncodingException, IOException, MarshallingException,
    SignatureException, TransformerException
  {
    init();
    EidasMetadataNode meta = new EidasMetadataNode(id, entityId, validUntil, sigCert, encCert, organisation,
                                                   techcontact, supportcontact, postEndpoint, spType,
                                                   supportedNameIdTypes);
    return meta.generate(signer);
  }

  /**
   * Parse metadata of another node, not accepting invalid signatures.
   *
   * @param is stream containing metadata
   * @param signer verification certificate (optional)
   * @return
   * @throws CertificateException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws ErrorCodeException
   * @throws InitializationException
   * @throws ComponentInitializationException
   */
  public static EidasMetadataNode parseMetaDataNode(InputStream is, X509Certificate signer)
    throws CertificateException, XMLParserException, UnmarshallingException, ErrorCodeException,
    InitializationException, ComponentInitializationException
  {
    init();
    return EidasMetadataNode.parse(is, signer, false);
  }

  /**
   * Parse metadata of another node.
   *
   * @param is stream containing metadata
   * @param signer verification certificate (optional)
   * @param continueOnInvalidSig <code>true</code> for allowing to continue on failed signature validation,
   *          <code>false</code> otherwise
   * @return
   * @throws CertificateException
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws ErrorCodeException
   * @throws InitializationException
   * @throws ComponentInitializationException
   */
  public static EidasMetadataNode parseMetaDataNode(InputStream is,
                                                    X509Certificate signer,
                                                    boolean continueOnInvalidSig)
    throws CertificateException, XMLParserException, UnmarshallingException, ErrorCodeException,
    InitializationException, ComponentInitializationException
  {
    init();
    return EidasMetadataNode.parse(is, signer, continueOnInvalidSig);
  }

  /**
   * Validates a saml message with the saml-schema-protocol-2_0.xsd, saml-schema-assertion-2_0.xsd,
   * xenc-schema.xsd, xmldsig-core-schema.xsd,NaturalPersonShema.xsd If the message is not valid a
   * SAXException will be thrown
   *
   * @param is the saml message as stream
   * @param resetStreamAfterValidation if u like to parse the given stream later u have to reset the stream
   * @throws SAXException if the given saml message is not vaild
   * @throws IOException if there is a problem to read the stream
   */
  public static void validateXMLRequest(InputStream is, boolean resetStreamAfterValidation)
    throws SAXException, IOException
  {

    SchemaFactory sf = Utils.getSchemaFactory();

    StreamSource s2 = new StreamSource(EidasSaml.class.getResourceAsStream("saml-schema-protocol-2_0.xsd"));
    StreamSource s1 = new StreamSource(EidasSaml.class.getResourceAsStream("saml-schema-assertion-2_0.xsd"));
    StreamSource s3 = new StreamSource(EidasSaml.class.getResourceAsStream("xenc-schema.xsd"));
    StreamSource s4 = new StreamSource(EidasSaml.class.getResourceAsStream("xmldsig-core-schema.xsd"));
    StreamSource s5 = new StreamSource(EidasSaml.class.getResourceAsStream("NaturalPersonShema.xsd"));

    Schema schema = sf.newSchema(new StreamSource[]{s5, s4, s3, s1, s2});
    Validator validator = Utils.getValidator(schema);
    validator.validate(new StreamSource(is));
    if (resetStreamAfterValidation)
    {
      is.reset();// this is imported if u try to parse the stream later
    }
  }

}
