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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
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
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
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
import de.governikus.eumw.eidasstarterkit.template.TemplateConstants;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.xmlsec.encryption.support.DecryptionUtils;


/**
 * @author hohnholt
 */
public class EidasResponse
{

  private static final long ONE_MINUTE_IN_MILLIS = 60000;// millisecs

  private String id;

  private String destination;

  private String recipient;

  private String issuer;

  private String inResponseTo;

  private String issueInstant;

  private EidasLoA loa;

  private EidasEncrypter encrypter;

  private EidasSigner signer;

  private final List<EidasAttribute> attributes;

  private EidasNameId nameId = null;

  private Response openSamlResp = null;

  private EidasResponse()
  {
    attributes = new ArrayList<>();
  }

  public EidasResponse(String destination,
                       String recipient,
                       EidasNameId nameid,
                       String inResponseTo,
                       String issuer,
                       EidasLoA loa,
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
    issueInstant = Constants.format(new Date());
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
                EidasLoA loa,
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
    issueInstant = Constants.format(new Date());
    this.encrypter = encrypter;
    this.signer = signer;
    this.attributes = att;
  }

  public byte[] generateErrorRsp(ErrorCode code, String... msg) throws IOException, XMLParserException,
    UnmarshallingException, CertificateEncodingException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException, ComponentInitializationException
  {
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    byte[] returnValue;
    String respTemp = TemplateLoader.getTemplateByName("failresp");
    respTemp = respTemp.replace(TemplateConstants.IN_RESPONSE_TO, inResponseTo);
    respTemp = respTemp.replace(TemplateConstants.ISSUE_INSTANT, issueInstant);
    respTemp = respTemp.replace(TemplateConstants.ISSUER, issuer);
    respTemp = respTemp.replace(TemplateConstants.ID, id);
    respTemp = respTemp.replace(TemplateConstants.DESTINATION, destination);
    respTemp = respTemp.replace(TemplateConstants.CODE, errorCodeToSamlStatus.get(code));
    if (msg == null)
    {
      respTemp = respTemp.replace(TemplateConstants.ERR_MSG, code.toDescription());
    }
    else
    {
      respTemp = respTemp.replace(TemplateConstants.ERR_MSG, code.toDescription(msg));
    }
    List<Signature> sigs = new ArrayList<>();

    try (InputStream is = new ByteArrayInputStream(respTemp.getBytes(StandardCharsets.UTF_8)))
    {
      Document inCommonMDDoc = ppMgr.parse(is);
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      // Get apropriate unmarshaller
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      Response resp = (Response)unmarshaller.unmarshall(metadataRoot);

      XMLSignatureHandler.addSignature(resp,
                                       signer.getSigKey(),
                                       signer.getSigCert(),
                                       signer.getSigType(),
                                       signer.getSigDigestAlg());

      if (resp.getSignature() != null)
      {
        sigs.add(resp.getSignature());
      }

      Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                                                      .getMarshaller(resp.getElementQName());
      Element all = rm.marshall(resp);
      if (resp.getSignature() != null)
      {
        sigs.add(resp.getSignature());
      }
      Signer.signObjects(sigs);

      openSamlResp = resp;
      Transformer trans = Utils.getTransformer();
      trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      // Please note: you cannot format the output without breaking signature!
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
      {
        trans.transform(new DOMSource(all), new StreamResult(bout));
        returnValue = bout.toByteArray();
      }
    }
    return returnValue;
  }

  byte[] generate() throws XMLParserException, IOException, UnmarshallingException,
    CertificateEncodingException, EncryptionException, MarshallingException, SignatureException,
    TransformerFactoryConfigurationError, TransformerException, ComponentInitializationException
  {
    byte[] returnValue;

    String notBefore = Constants.format(new Date());
    String notAfter = Constants.format(new Date(new Date().getTime() + (10 * ONE_MINUTE_IN_MILLIS)));

    if (nameId == null)
    {
      throw new XMLParserException("Document does not contains a NameID value");
    }
    StringBuilder attributeString = new StringBuilder();
    for ( EidasAttribute eidasAtt : this.attributes )
    {
      attributeString.append(eidasAtt.generate());
    }
    String assoTemp = TemplateLoader.getTemplateByName("asso");
    assoTemp = assoTemp.replace(TemplateConstants.NAME_FORMAT, nameId.getType().value);
    assoTemp = assoTemp.replace(TemplateConstants.NAME_ID, nameId.getValue());
    assoTemp = assoTemp.replace(TemplateConstants.ASSERTION_ID, "_" + Utils.generateUniqueID());
    assoTemp = assoTemp.replace(TemplateConstants.RECIPIENT, recipient);
    assoTemp = assoTemp.replace(TemplateConstants.AUTHN_INSTANT, issueInstant);
    assoTemp = assoTemp.replace(TemplateConstants.LOA, loa.value);
    assoTemp = assoTemp.replace(TemplateConstants.SESSION_INDEX, "_" + Utils.generateUniqueID());
    assoTemp = assoTemp.replace(TemplateConstants.ATTRIBUTES, attributeString.toString());
    assoTemp = assoTemp.replace(TemplateConstants.NOT_BEFORE, notBefore);
    assoTemp = assoTemp.replace(TemplateConstants.NOT_ON_OR_AFTER, notAfter);
    assoTemp = assoTemp.replace(TemplateConstants.IN_RESPONSE_TO, inResponseTo);
    assoTemp = assoTemp.replace(TemplateConstants.ISSUE_INSTANT, issueInstant);
    assoTemp = assoTemp.replace(TemplateConstants.ISSUER, issuer);
    assoTemp = assoTemp.replace(TemplateConstants.ID, id);
    assoTemp = assoTemp.replace(TemplateConstants.DESTINATION, destination);

    String generatedAssertionXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + assoTemp;
    Assertion ass = null;
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    try (InputStream is = new ByteArrayInputStream(generatedAssertionXML.getBytes(StandardCharsets.UTF_8)))
    {
      Document inCommonMDDoc = ppMgr.parse(is);
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      // Get apropriate unmarshaller
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      ass = (Assertion)unmarshaller.unmarshall(metadataRoot);
    }

    Assertion[] assertions = new Assertion[]{ass};

    String respTemp = TemplateLoader.getTemplateByName("resp");
    respTemp = respTemp.replace(TemplateConstants.IN_RESPONSE_TO, inResponseTo);
    respTemp = respTemp.replace(TemplateConstants.ISSUE_INSTANT, issueInstant);
    respTemp = respTemp.replace(TemplateConstants.ISSUER, issuer);
    respTemp = respTemp.replace(TemplateConstants.ID, id);
    respTemp = respTemp.replace(TemplateConstants.DESTINATION, destination);

    List<Signature> sigs = new ArrayList<>();

    try (InputStream is = new ByteArrayInputStream(respTemp.getBytes(StandardCharsets.UTF_8)))
    {
      Document inCommonMDDoc = ppMgr.parse(is);
      Element metadataRoot = inCommonMDDoc.getDocumentElement();
      // Get apropriate unmarshaller
      UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
      Response resp = (Response)unmarshaller.unmarshall(metadataRoot);

      XMLSignatureHandler.addSignature(resp,
                                       signer.getSigKey(),
                                       signer.getSigCert(),
                                       signer.getSigType(),
                                       signer.getSigDigestAlg());
      for ( Assertion a : assertions )
      {
        a.setParent(null);
        resp.getEncryptedAssertions().add(this.encrypter.encrypter.encrypt(a));
      }

      if (resp.getSignature() != null)
      {
        sigs.add(resp.getSignature());
      }

      Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                                                      .getMarshaller(resp.getElementQName());
      Element all = rm.marshall(resp);
      if (resp.getSignature() != null)
      {
        sigs.add(resp.getSignature());
      }
      Signer.signObjects(sigs);

      openSamlResp = resp;
      Transformer trans = Utils.getTransformer();
      trans.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      // Please note: you cannot format the output without breaking signature!
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
      {
        trans.transform(new DOMSource(all), new StreamResult(bout));
        returnValue = bout.toByteArray();
      }
    }
    return returnValue;
  }

  public String getId()
  {
    return id;
  }

  public String getRecipient()
  {
    return recipient;
  }

  public String getDestination()
  {
    return destination;
  }

  public String getIssuer()
  {
    return issuer;
  }

  public String getInResponseTo()
  {
    return inResponseTo;
  }

  public String getIssueInstant()
  {
    return issueInstant;
  }

  public void addAttribute(EidasAttribute e)
  {
    attributes.add(e);
  }

  public List<EidasAttribute> getAttributes()
  {
    return attributes;
  }

  public EidasNameId getNameId()
  {
    return nameId;
  }

  public void setNameId(EidasNameId nameid)
  {
    this.nameId = nameid;
  }

  public Response getOpenSamlResponse()
  {
    return openSamlResp;
  }

  public static EidasResponse parse(InputStream is,
                                    X509KeyPair[] decryptionKeyPairs,
                                    X509Certificate[] signatureAuthors)
    throws XMLParserException, UnmarshallingException, ErrorCodeException, ComponentInitializationException
  {
    EidasResponse eidasResp = new EidasResponse();
    List<X509Certificate> trustedAnchorList = getTrustedAnchorList(signatureAuthors);
    List<Credential> decryptionCredentialList = getDecryptionCredentialList(decryptionKeyPairs);
    Response resp = getOpenSamlResponse(is);
    eidasResp.openSamlResp = resp;

    checkSignature(resp.getSignature(), trustedAnchorList);
    processSAMLResponse(eidasResp, trustedAnchorList, decryptionCredentialList, resp);
    eidasResp.id = resp.getID();
    eidasResp.destination = resp.getDestination();
    eidasResp.inResponseTo = resp.getInResponseTo();
    eidasResp.issueInstant = Constants.format(resp.getIssueInstant().toDate());
    eidasResp.issuer = resp.getIssuer().getDOM().getTextContent();
    eidasResp.openSamlResp = resp;

    return eidasResp;
  }

  private static void processSAMLResponse(EidasResponse eidasResp,
                                          List<X509Certificate> trustedAnchorList,
                                          List<Credential> decryptionCredentialList,
                                          Response resp)
    throws ErrorCodeException
  {
    if (!StatusCode.SUCCESS.equals(resp.getStatus().getStatusCode().getValue()))
    {
      ErrorCode code = findErrorCode(resp.getStatus().getStatusCode().getValue());
      if (code == null)
      {
        code = ErrorCode.INTERNAL_ERROR;
        throw new ErrorCodeException(code,
                                     "Unkown statuscode " + resp.getStatus().getStatusCode().getValue());
      }
      // Error respose, so un-encrypted assertion!
      for ( Assertion assertion : resp.getAssertions() )
      {
        setEidasResponseNameIdFromAssertion(eidasResp, assertion);
      }
    }
    else
    {
      Decrypter decr = new Decrypter(DecryptionUtils.createDecryptionParameters(decryptionCredentialList.toArray(new Credential[0])));
      decr.setRootInNewDocument(true);

      List<Assertion> assertions = collectDecryptedAssertions(resp, decr);

      processAssertions(eidasResp, trustedAnchorList, assertions);

      resp.getAssertions().clear();
      resp.getAssertions().addAll(assertions);
      eidasResp.recipient = getAudience(resp);
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
      for ( AttributeStatement attStat : assertion.getAttributeStatements() )
      {
        processAttributes(eidasResp, attStat);
      }
    }
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
      XMLObject attributeValue = att.getAttributeValues().get(0); // IN EIDAS there is just one value
                                                                  // except familyname!
      Element domElement = attributeValue.getDOM();
      EidasAttribute eidasAttribute = personAttributes.getInstance();
      if (eidasAttribute instanceof AbstractNonLatinScriptAttribute)
      {
        AbstractNonLatinScriptAttribute abstractAttribute = (AbstractNonLatinScriptAttribute)eidasAttribute;
        abstractAttribute.setLatinScript(att.getAttributeValues().get(0).getDOM().getTextContent());
        if (att.getAttributeValues().size() == 2)
        {
          abstractAttribute.setNonLatinScript(att.getAttributeValues().get(1).getDOM().getTextContent());
        }
      }
      else
      {
        eidasAttribute.setLatinScript(domElement.getTextContent());
      }
      eidasResp.attributes.add(eidasAttribute);
    }
  }

  private static EidasPersonAttributes getEidasPersonAttributes(Attribute att)
  {
    EidasPersonAttributes personAttributes;
    /* Get Person Attribute from the DOM */
    try
    {
      personAttributes = EidasNaturalPersonAttributes.getValueOf(att.getName());
    }
    catch (ErrorCodeException e1)
    {
      try
      {
        personAttributes = EidasLegalPersonAttributes.getValueOf(att.getName());
      }
      catch (ErrorCodeException e2)
      {
        throw new IllegalArgumentException("No attribute known with name: " + att.getName());
      }
    }
    return personAttributes;
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

  private static Map<ErrorCode, String> errorCodeToSamlStatus = new EnumMap<>(ErrorCode.class);
  static
  {
    errorCodeToSamlStatus.put(ErrorCode.SUCCESS, StatusCode.SUCCESS);
    errorCodeToSamlStatus.put(ErrorCode.ERROR, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.INTERNAL_ERROR, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.UNSIGNED_ASSERTIONCONSUMER_URL, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.INVALID_SESSION_ID, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.TOO_MANY_OPEN_SESSIONS, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.MISSING_REQUEST_ID, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.SIGNATURE_CHECK_FAILED, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.SIGNATURE_MISSING, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_REQUEST_SYNTAX, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.AUTHORIZATION_FAILED, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.AUTHORIZATION_UNFINISHED, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.UNKNOWN_PROVIDER, StatusCode.REQUEST_UNSUPPORTED);
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_CONFIGURATION, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.CANNOT_ACCESS_CREDENTIALS, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.INVALID_CERTIFICATE, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_ACCESS_METHOD, StatusCode.REQUEST_UNSUPPORTED);
    errorCodeToSamlStatus.put(ErrorCode.SOAP_RESPONSE_WRONG_SYNTAX, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.UNENCRYPTED_ACCESS_NOT_ALLOWED, StatusCode.REQUEST_UNSUPPORTED);
    errorCodeToSamlStatus.put(ErrorCode.OUTDATED_ASSERTION, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.WRONG_DESTINATION, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.UNEXPECTED_EVENT, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.OUTDATED_REQUEST, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.REQUEST_FROM_FUTURE, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.DUPLICATE_REQUEST_ID, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.EID_ERROR, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.ECARD_ERROR, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.EID_MISSING_TERMINAL_RIGHTS, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.EID_MISSING_ARGUMENT, StatusCode.RESPONDER);
    errorCodeToSamlStatus.put(ErrorCode.PASSWORD_EXPIRED, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.PASSWORD_LOCKED, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.CANNOT_DECRYPT, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.ILLEGAL_PSK, StatusCode.REQUESTER);
    errorCodeToSamlStatus.put(ErrorCode.CLIENT_ERROR, StatusCode.AUTHN_FAILED);
    errorCodeToSamlStatus.put(ErrorCode.PROXY_COUNT_EXCEEDED, StatusCode.PROXY_COUNT_EXCEEDED);
    errorCodeToSamlStatus.put(ErrorCode.NO_SUPPORTED_IDP, StatusCode.NO_SUPPORTED_IDP);
    errorCodeToSamlStatus.put(ErrorCode.REQUEST_DENIED, StatusCode.REQUEST_DENIED);
    errorCodeToSamlStatus.put(ErrorCode.CANCELLATION_BY_USER, StatusCode.AUTHN_FAILED);
  }

  private static ErrorCode findErrorCode(String s)
  {
    for ( Entry<ErrorCode, String> e : errorCodeToSamlStatus.entrySet() )
    {
      if (e.getValue().equals(s))
      {
        return e.getKey();
      }
    }
    return null;
  }
}
