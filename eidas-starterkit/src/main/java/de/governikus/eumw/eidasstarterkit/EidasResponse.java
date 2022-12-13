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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractNonLatinScriptAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import lombok.Getter;
import lombok.Setter;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.common.EidasConstants;
import se.litsec.eidas.opensaml.ext.attributes.CurrentAddressType;
import se.swedenconnect.opensaml.xmlsec.encryption.support.DecryptionUtils;


/**
 * @author hohnholt
 */
public class EidasResponse
{

  // List of Strings contains the statusCode in the right order. The first Code is the outer statusCode.
  private static Map<ErrorCode, List<String>> errorCodeToSamlStatus = new EnumMap<>(ErrorCode.class);

  static
  {
    errorCodeToSamlStatus.put(ErrorCode.SUCCESS, Collections.singletonList(StatusCode.SUCCESS));
    errorCodeToSamlStatus.put(ErrorCode.ERROR, Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.INTERNAL_ERROR, Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.UNSIGNED_ASSERTIONCONSUMER_URL,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.INVALID_SESSION_ID, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.TOO_MANY_OPEN_SESSIONS,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.MISSING_REQUEST_ID, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.SIGNATURE_CHECK_FAILED,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.SIGNATURE_MISSING, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.AUTHORIZATION_FAILED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.AUTHORIZATION_UNFINISHED,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.UNKNOWN_PROVIDER,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.REQUEST_UNSUPPORTED));
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_CONFIGURATION,
                              Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.CANNOT_ACCESS_CREDENTIALS,
                              Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.INVALID_CERTIFICATE,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_ACCESS_METHOD,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.REQUEST_UNSUPPORTED));
    errorCodeToSamlStatus.put(ErrorCode.SOAP_RESPONSE_WRONG_SYNTAX,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.UNENCRYPTED_ACCESS_NOT_ALLOWED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.REQUEST_UNSUPPORTED));
    errorCodeToSamlStatus.put(ErrorCode.OUTDATED_ASSERTION, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.WRONG_DESTINATION, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.UNEXPECTED_EVENT, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.OUTDATED_REQUEST, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.REQUEST_FROM_FUTURE, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.DUPLICATE_REQUEST_ID,
                              Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.EID_ERROR, Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.ECARD_ERROR,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.EID_MISSING_TERMINAL_RIGHTS,
                              Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.EID_MISSING_ARGUMENT,
                              Collections.singletonList(StatusCode.RESPONDER));
    errorCodeToSamlStatus.put(ErrorCode.PASSWORD_EXPIRED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.PASSWORD_LOCKED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.CANNOT_DECRYPT, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_PSK, Collections.singletonList(StatusCode.REQUESTER));
    errorCodeToSamlStatus.put(ErrorCode.CLIENT_ERROR,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.PROXY_COUNT_EXCEEDED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.PROXY_COUNT_EXCEEDED));
    errorCodeToSamlStatus.put(ErrorCode.NO_SUPPORTED_IDP,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.NO_SUPPORTED_IDP));
    errorCodeToSamlStatus.put(ErrorCode.REQUEST_DENIED,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED));
    errorCodeToSamlStatus.put(ErrorCode.CANCELLATION_BY_USER,
                              Arrays.asList(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED));
    errorCodeToSamlStatus.put(ErrorCode.INVALID_NAME_ID_TYPE,
                              Arrays.asList(StatusCode.REQUESTER, StatusCode.INVALID_NAMEID_POLICY));
  }

  @Getter
  private final List<EidasAttribute> attributes;

  @Getter
  private String id;

  @Getter
  private String destination;

  @Getter
  private String recipient;

  @Getter
  private String issuer;

  @Getter
  private String inResponseTo;

  @Getter
  private String issueInstant;

  @Getter
  @Setter
  private EidasLoaEnum loa;

  private EidasEncrypter encrypter;

  private EidasSigner signer;

  @Getter
  @Setter
  private EidasNameId nameId;

  @Getter
  private Response openSamlResponse;

  private EidasResponse()
  {
    attributes = new ArrayList<>();
  }

  public EidasResponse(String destination,
                       String recipient,
                       EidasNameId nameid,
                       String inResponseTo,
                       String issuer,
                       EidasLoaEnum loa,
                       EidasSigner signer,
                       EidasEncrypter encrypter)
  {
    id = "_" + Utils.generateUniqueID();
    this.nameId = nameid;
    this.destination = destination;
    this.recipient = recipient;
    this.inResponseTo = inResponseTo;
    this.issuer = issuer;
    this.loa = loa;
    issueInstant = Instant.now().toString();
    this.encrypter = encrypter;
    this.signer = signer;
    attributes = new ArrayList<>();
  }

  EidasResponse(List<EidasAttribute> att,
                String destination,
                String recipient,
                EidasNameId nameid,
                String inResponseTo,
                String issuer,
                EidasLoaEnum loa,
                EidasSigner signer,
                EidasEncrypter encrypter)
  {
    id = "_" + Utils.generateUniqueID();
    this.nameId = nameid;
    this.destination = destination;
    this.recipient = recipient;
    this.inResponseTo = inResponseTo;
    this.issuer = issuer;
    this.loa = loa;
    issueInstant = Instant.now().toString();
    this.encrypter = encrypter;
    this.signer = signer;
    this.attributes = att;
  }

  public static EidasResponse parse(InputStream is,
                                    X509KeyPair[] decryptionKeyPairs,
                                    X509Certificate... signatureAuthors)
    throws XMLParserException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    EidasResponse eidasResp = new EidasResponse();
    List<X509Certificate> trustedAnchorList = getTrustedAnchorList(signatureAuthors);
    List<Credential> decryptionCredentialList = getDecryptionCredentialList(decryptionKeyPairs);
    Response resp = getOpenSamlResponse(is);
    eidasResp.openSamlResponse = resp;

    checkSignature(resp.getSignature(), trustedAnchorList);
    processSAMLResponse(eidasResp, trustedAnchorList, decryptionCredentialList, resp);
    eidasResp.id = resp.getID();
    eidasResp.destination = resp.getDestination();
    eidasResp.inResponseTo = resp.getInResponseTo();
    eidasResp.issueInstant = resp.getIssueInstant().toString();
    eidasResp.issuer = resp.getIssuer().getDOM().getTextContent();
    eidasResp.openSamlResponse = resp;

    return eidasResp;
  }

  private static void processSAMLResponse(EidasResponse eidasResp,
                                          List<X509Certificate> trustedAnchorList,
                                          List<Credential> decryptionCredentialList,
                                          Response resp)
    throws ErrorCodeException
  {
    if (StatusCode.SUCCESS.equals(resp.getStatus().getStatusCode().getValue()))
    {
      Decrypter decr = new Decrypter(DecryptionUtils.createDecryptionParameters(decryptionCredentialList.toArray(new Credential[0])));
      decr.setRootInNewDocument(true);

      List<Assertion> assertions = collectDecryptedAssertions(resp, decr);

      processAssertions(eidasResp, trustedAnchorList, assertions);

      resp.getAssertions().clear();
      resp.getAssertions().addAll(assertions);
      eidasResp.recipient = getAudience(resp);
    }
    else
    {
      ErrorCode code = findErrorCode(resp.getStatus().getStatusCode().getValue());
      if (code == null)
      {
        code = ErrorCode.INTERNAL_ERROR;
        throw new ErrorCodeException(code,
                                     "Unkown statuscode " + resp.getStatus().getStatusCode().getValue());
      }
      // Error response, so un-encrypted assertion!
      for ( Assertion assertion : resp.getAssertions() )
      {
        setEidasResponseNameIdFromAssertion(eidasResp, assertion);
      }
    }
  }

  private static void processAssertions(EidasResponse eidasResp,
                                        List<X509Certificate> trustedAnchorList,
                                        List<Assertion> assertions)
    throws ErrorCodeException
  {
    for ( Assertion assertion : assertions )
    {
      checkSignature(trustedAnchorList, assertion);
      setEidasResponseNameIdFromAssertion(eidasResp, assertion);
      setLevelOfAssuranceFromAssertion(eidasResp, assertion);
      for ( AttributeStatement attStat : assertion.getAttributeStatements() )
      {
        processAttributes(eidasResp, attStat);
      }
    }
  }

  private static void setLevelOfAssuranceFromAssertion(EidasResponse eidasResp, Assertion assertion)
  {
    String loa = assertion.getAuthnStatements()
                          .get(0)
                          .getAuthnContext()
                          .getAuthnContextClassRef()
                          .getURI();
    EidasLoaEnum loaEnum = EidasLoaEnum.parse(loa);
    eidasResp.setLoa(loaEnum);
  }

  private static void processAttributes(EidasResponse eidasResp, AttributeStatement attStat)
  {
    for ( Attribute att : attStat.getAttributes() )
    {
      if (att.getAttributeValues().isEmpty())
      {
        continue;
      }

      EidasPersonAttributes personAttributes = getEidasPersonAttributes(att);
      EidasAttribute eidasAttribute = personAttributes.getInstance();
      XMLObject attributeValue = att.getAttributeValues().get(0);
      if (eidasAttribute instanceof AbstractNonLatinScriptAttribute)
      {
        AbstractNonLatinScriptAttribute attribute = (AbstractNonLatinScriptAttribute)eidasAttribute;
        attribute.setValue(attributeValue.getDOM().getTextContent());
        if (att.getAttributeValues().size() == 2)
        {
          attribute.setNonLatinScript(att.getAttributeValues().get(1).getDOM().getTextContent());
        }
      }
      else if (eidasAttribute instanceof CurrentAddressAttribute
               && attributeValue instanceof CurrentAddressType)
      {
        CurrentAddressAttribute attribute = (CurrentAddressAttribute)eidasAttribute;
        CurrentAddressType cat = (CurrentAddressType)attributeValue;
        attribute.setFromCurrentAddressType(cat);
      }
      else
      {
        eidasAttribute.setValue(attributeValue.getDOM().getTextContent());
      }
      eidasResp.attributes.add(eidasAttribute);
    }
  }

  private static EidasPersonAttributes getEidasPersonAttributes(Attribute att)
  {
    /* Get Person Attribute from the DOM */
    try
    {
      return EidasNaturalPersonAttributes.getValueOf(att.getName());
    }
    catch (ErrorCodeException e1)
    {
      throw new IllegalArgumentException("No attribute known with name: " + att.getName());
    }
  }

  private static void checkSignature(List<X509Certificate> trustedAnchorList, Assertion assertion)
    throws ErrorCodeException
  {
    if (null != assertion.getSignature())
    { // signature in assertion may be null
      checkSignature(assertion.getSignature(), trustedAnchorList);
    }
  }

  private static void setEidasResponseNameIdFromAssertion(EidasResponse eidasResp, Assertion assertion)
    throws ErrorCodeException
  {
    if (eidasResp.nameId == null)
    {
      EidasNameIdType type = EidasNameIdType.getValueOf(assertion.getSubject().getNameID().getFormat());
      if (type == EidasNameIdType.PERSISTENT)
      {
        eidasResp.nameId = new EidasPersistentNameId(assertion.getSubject().getNameID().getValue());
      }
      else if (type == EidasNameIdType.TRANSIENT)
      {
        eidasResp.nameId = new EidasTransientNameId(assertion.getSubject().getNameID().getValue());
      }
      else
      {
        eidasResp.nameId = new EidasUnspecifiedNameId(assertion.getSubject().getNameID().getValue());
      }
    }
  }

  private static List<Assertion> collectDecryptedAssertions(Response resp, Decrypter decr)
    throws ErrorCodeException
  {
    List<Assertion> assertions = new ArrayList<>();

    for ( EncryptedAssertion noitressa : resp.getEncryptedAssertions() )
    {
      try
      {
        assertions.add(decr.decrypt(noitressa));
      }
      catch (DecryptionException e)
      {
        throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT, e);
      }
    }

    return assertions;
  }

  private static Response getOpenSamlResponse(InputStream is)
    throws ComponentInitializationException, XMLParserException, UnmarshallingException
  {
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    // Get apropriate unmarshaller
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    return (Response)unmarshaller.unmarshall(metadataRoot);
  }

  private static List<X509Certificate> getTrustedAnchorList(X509Certificate... signatureAuthors)
    throws ErrorCodeException
  {
    if (signatureAuthors == null || signatureAuthors.length == 0)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }
    return new LinkedList<>(Arrays.asList(signatureAuthors));
  }

  private static List<Credential> getDecryptionCredentialList(X509KeyPair... decryptionKeyPairs)
    throws ErrorCodeException
  {
    if (decryptionKeyPairs == null || decryptionKeyPairs.length == 0)
    {
      throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT);
    }

    List<Credential> decryptionCredentialList = new LinkedList<>();
    for ( X509KeyPair pair : decryptionKeyPairs )
    {
      decryptionCredentialList.add(CredentialSupport.getSimpleCredential(pair.getCert(), pair.getKey()));
    }

    return decryptionCredentialList;
  }

  private static String getAudience(Response resp) throws ErrorCodeException
  {
    return resp.getAssertions()
               .stream()
               .findFirst()
               .orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR, "Missing Assertion in response."))
               .getConditions()
               .getAudienceRestrictions()
               .stream()
               .findFirst()
               .orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR,
                                                         "Missing AudienceRestrictions in response."))
               .getAudiences()
               .stream()
               .findFirst()
               .orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR, "Missing Audiences in response."))
               .getAudienceURI();
  }

  private static void checkSignature(Signature sig, List<X509Certificate> trustedAnchorList)
    throws ErrorCodeException
  {
    if (sig == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }
    XMLSignatureHandler.checkSignature(sig,
                                       trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));
  }

  private static ErrorCode findErrorCode(String s)
  {
    for ( Entry<ErrorCode, List<String>> e : errorCodeToSamlStatus.entrySet() )
    {
      if (e.getValue().contains(s))
      {
        return e.getKey();
      }
    }
    return null;
  }

  public byte[] generateErrorRsp(ErrorCode code, String... msg)
    throws IOException, CertificateEncodingException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException
  {
    Response response = new ResponseBuilder().buildObject();
    response.setDestination(destination);
    response.setInResponseTo(inResponseTo);
    response.setIssueInstant(Instant.now());
    response.setID(id);

    setSamlIssuer(response);
    setSamlStatusError(response, code, msg);

    List<Signature> signatures = new ArrayList<>();
    XMLSignatureHandler.addSignature(response,
                                     signer.getSigKey(),
                                     signer.getSigCert(),
                                     signer.getSigType(),
                                     signer.getSigDigestAlg());

    if (response.getSignature() != null)
    {
      signatures.add(response.getSignature());
    }

    return samlToByteArray(response, signatures);
  }

  byte[] generate() throws XMLParserException, IOException, CertificateEncodingException, EncryptionException,
    MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException
  {


    if (nameId == null)
    {
      throw new XMLParserException("Document does not contains a NameID value");
    }
    Instant now = Instant.now();

    Assertion assertion = new AssertionBuilder().buildObject();
    assertion.getNamespaceManager()
             .registerNamespaceDeclaration(new Namespace(EidasConstants.EIDAS_NP_NS,
                                                         EidasConstants.EIDAS_NP_PREFIX));
    assertion.setIssueInstant(now);
    assertion.setID("_" + Utils.generateUniqueID());

    setSamlIssuer(assertion);
    setSamlSubject(assertion, now);
    setSamlConditions(assertion, now);
    setSamlAuthnStatement(assertion, now);
    setSamlAttribute(assertion);

    Response response = new ResponseBuilder().buildObject();
    response.setDestination(destination);
    response.setID(id);
    response.setInResponseTo(inResponseTo);
    response.setIssueInstant(now);
    setSamlIssuer(response);
    setSamlStatusSuccess(response);

    List<Signature> signatures = new ArrayList<>();
    XMLSignatureHandler.addSignature(response,
                                     signer.getSigKey(),
                                     signer.getSigCert(),
                                     signer.getSigType(),
                                     signer.getSigDigestAlg());
    assertion.setParent(null);
    response.getEncryptedAssertions().add(this.encrypter.encrypter.encrypt(assertion));

    if (response.getSignature() != null)
    {
      signatures.add(response.getSignature());
    }

    return samlToByteArray(response, signatures);
  }

  private byte[] samlToByteArray(Response response, List<Signature> signatures)
    throws IOException, TransformerException, MarshallingException, SignatureException
  {

    Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                                                    .getMarshaller(response.getElementQName());
    Element all = rm.marshall(response);
    Signer.signObjects(signatures);

    openSamlResponse = response;
    Transformer trans = Utils.getTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
    // Please note: you cannot format the output without breaking signature!
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      return bout.toByteArray();
    }
  }

  void setSamlStatusError(Response response, ErrorCode code, String... msg)
  {
    Status status = new StatusBuilder().buildObject();
    StatusCode statusCode = new StatusCodeBuilder().buildObject();
    List<String> samlStatusCodes = errorCodeToSamlStatus.get(code);
    statusCode.setValue(samlStatusCodes.get(0));
    if (samlStatusCodes.size() > 1)
    {
      StatusCode statusCodeInner = new StatusCodeBuilder().buildObject();
      statusCodeInner.setValue(samlStatusCodes.get(1));
      statusCode.setStatusCode(statusCodeInner);
    }
    status.setStatusCode(statusCode);
    StatusMessage statusMessage = new StatusMessageBuilder().buildObject();
    if (msg == null)
    {
      statusMessage.setValue(code.toDescription());
    }
    else
    {
      statusMessage.setValue(code.toDescription(msg));
    }
    status.setStatusMessage(statusMessage);
    response.setStatus(status);
  }

  private void setSamlStatusSuccess(Response response)
  {
    Status status = new StatusBuilder().buildObject();
    StatusCode statusCode = new StatusCodeBuilder().buildObject();
    statusCode.setValue(StatusCode.SUCCESS);
    status.setStatusCode(statusCode);
    response.setStatus(status);
  }

  private void setSamlIssuer(Response response)
  {
    Issuer issuerSaml = new IssuerBuilder().buildObject();
    issuerSaml.setValue(issuer);
    response.setIssuer(issuerSaml);
  }

  private void setSamlIssuer(Assertion assertion)
  {
    Issuer issuerSaml = new IssuerBuilder().buildObject();
    issuerSaml.setValue(issuer);
    assertion.setIssuer(issuerSaml);
  }

  private void setSamlSubject(Assertion assertion, Instant now)
  {
    Subject subject = new SubjectBuilder().buildObject();
    NameID nameID = new NameIDBuilder().buildObject();
    nameID.setValue(nameId.getValue());
    nameID.setFormat(nameId.getType().getValue());
    subject.setNameID(nameID);

    SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
    subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
    SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
    subjectConfirmationData.setInResponseTo(inResponseTo);
    subjectConfirmationData.setNotBefore(now);
    subjectConfirmationData.setNotOnOrAfter(now.plus(10, ChronoUnit.MINUTES));
    subjectConfirmationData.setRecipient(destination);

    subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
    subject.getSubjectConfirmations().add(subjectConfirmation);

    assertion.setSubject(subject);
  }

  private void setSamlConditions(Assertion assertion, Instant now)
  {
    Conditions conditions = new ConditionsBuilder().buildObject();
    AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
    Audience audience = new AudienceBuilder().buildObject();
    audience.setURI(recipient);
    audienceRestriction.getAudiences().add(audience);
    conditions.getAudienceRestrictions().add(audienceRestriction);
    conditions.setNotBefore(now);
    conditions.setNotOnOrAfter(now.plus(10, ChronoUnit.MINUTES));
    assertion.setConditions(conditions);
  }

  private void setSamlAuthnStatement(Assertion assertion, Instant now)
  {
    AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
    authnStatement.setAuthnInstant(now);
    authnStatement.setSessionIndex("_" + Utils.generateUniqueID());
    AuthnContext authnContext = new AuthnContextBuilder().buildObject();

    AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
    authnContextClassRef.setURI(loa.getUri());
    authnContext.setAuthnContextClassRef(authnContextClassRef);
    authnStatement.setAuthnContext(authnContext);
    assertion.getAuthnStatements().add(authnStatement);
  }

  private void setSamlAttribute(Assertion assertion)
  {
    AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
    for ( EidasAttribute eidasAttribute : this.attributes )
    {
      Attribute att = eidasAttribute.generate();
      attributeStatement.getAttributes().add(att);
    }
    assertion.getAttributeStatements().add(attributeStatement);
  }

  public void addAttribute(EidasAttribute e)
  {
    attributes.add(e);
  }
}
