/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
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
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


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
    String notBefore = Constants.format(new Date());
    String notAfter = Constants.format(new Date(new Date().getTime() + (10 * ONE_MINUTE_IN_MILLIS)));

    String assoTemp = TemplateLoader.getTemplateByName("failasso");

    if (nameId == null)
    {
      nameId = new EidasTransientNameId("Error in process, therefore no NameID");
    }

    assoTemp = assoTemp.replace("$AssertionId", "_" + Utils.generateUniqueID());
    assoTemp = assoTemp.replace("$IssueInstant", issueInstant);
    assoTemp = assoTemp.replace("$Issuer", issuer);
    assoTemp = assoTemp.replace("$NameFormat", nameId.getType().value);
    assoTemp = assoTemp.replace("$NameID", nameId.getValue());
    assoTemp = assoTemp.replace("$InResponseTo", inResponseTo);
    assoTemp = assoTemp.replace("$NotOnOrAfter", notAfter);
    assoTemp = assoTemp.replace("$Recipient", recipient);
    assoTemp = assoTemp.replace("$NotBefore", notBefore);

    assoTemp = assoTemp.replace("$AuthnInstant", issueInstant);
    assoTemp = assoTemp.replace("$LoA", loa.value);

    String respTemp = TemplateLoader.getTemplateByName("failresp");
    respTemp = respTemp.replace("$InResponseTo", inResponseTo);
    respTemp = respTemp.replace("$IssueInstant", issueInstant);
    respTemp = respTemp.replace("$Issuer", issuer);
    respTemp = respTemp.replace("$Id", id);
    respTemp = respTemp.replace("$Destination", destination);
    respTemp = respTemp.replace("$Code", errorCodeToSamlStatus.get(code));
    if (msg == null)
    {
      respTemp = respTemp.replace("$ErrMsg", code.toDescription());
    }
    else
    {
      respTemp = respTemp.replace("$ErrMsg", code.toDescription(msg));
    }
    respTemp = respTemp.replace("$Assertion", assoTemp);

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
    assoTemp = assoTemp.replace("$NameFormat", nameId.getType().value);
    assoTemp = assoTemp.replace("$NameID", nameId.getValue());
    assoTemp = assoTemp.replace("$AssertionId", "_" + Utils.generateUniqueID());
    assoTemp = assoTemp.replace("$Recipient", recipient);
    assoTemp = assoTemp.replace("$AuthnInstant", issueInstant);
    assoTemp = assoTemp.replace("$LoA", loa.value);
    assoTemp = assoTemp.replace("$SessionIndex", "_" + Utils.generateUniqueID());
    assoTemp = assoTemp.replace("$attributes", attributeString.toString());
    assoTemp = assoTemp.replace("$NotBefore", notBefore);
    assoTemp = assoTemp.replace("$NotOnOrAfter", notAfter);
    assoTemp = assoTemp.replace("$InResponseTo", inResponseTo);
    assoTemp = assoTemp.replace("$IssueInstant", issueInstant);
    assoTemp = assoTemp.replace("$Issuer", issuer);
    assoTemp = assoTemp.replace("$Id", id);
    assoTemp = assoTemp.replace("$Destination", destination);

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
    respTemp = respTemp.replace("$InResponseTo", inResponseTo);
    respTemp = respTemp.replace("$IssueInstant", issueInstant);
    respTemp = respTemp.replace("$Issuer", issuer);
    respTemp = respTemp.replace("$Id", id);
    respTemp = respTemp.replace("$Destination", destination);

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
    List<Credential> decryptionCredentialList = new LinkedList<>();
    List<X509Certificate> trustedAnchorList = new LinkedList<>();

    if (decryptionKeyPairs == null)
    {
      throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT);
    }
    if (decryptionKeyPairs.length == 0)
    {
      throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT);
    }
    for ( X509KeyPair pair : decryptionKeyPairs )
    {
      decryptionCredentialList.add(CredentialSupport.getSimpleCredential(pair.getCert(), pair.getKey()));
    }

    if (signatureAuthors == null)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }
    if (signatureAuthors.length == 0)
    {
      throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
    }
    for ( X509Certificate author : signatureAuthors )
    {
      trustedAnchorList.add(author);
    }

    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    // Get apropriate unmarshaller
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    Response resp = (Response)unmarshaller.unmarshall(metadataRoot);
    eidasResp.openSamlResp = resp;

    checkSignature(resp.getSignature(), trustedAnchorList);
    if (!StatusCode.SUCCESS.equals(resp.getStatus().getStatusCode().getValue()))
    {
      ErrorCode code = findErrorCode(resp.getStatus().getStatusCode().getValue());
      if (code == null)
      {
        code = ErrorCode.INTERNAL_ERROR;
        throw new ErrorCodeException(code,
                                     "Unkown statuscode " + resp.getStatus().getStatusCode().getValue());
      }
      // Error respose, so un-encrypted asserion!
      for ( Assertion assertion : resp.getAssertions() )
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
    }
    else
    {
      List<EncryptedAssertion> decryptedAssertions = new ArrayList<>();
      List<Assertion> assertions = new ArrayList<>();

      StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(decryptionCredentialList);

      Decrypter decr = new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
      decr.setRootInNewDocument(true);

      for ( EncryptedAssertion noitressa : resp.getEncryptedAssertions() )
      {
        try
        {
          assertions.add(decr.decrypt(noitressa));
          decryptedAssertions.add(noitressa);
        }
        catch (DecryptionException e)
        {
          throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT, e);
        }
      }

      for ( Assertion assertion : assertions )
      {
        if (null != assertion.getSignature())
        { // signature in assertion may be null
          checkSignature(assertion.getSignature(), trustedAnchorList);
        }
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
        for ( AttributeStatement attStat : assertion.getAttributeStatements() )
        {

          for ( Attribute att : attStat.getAttributes() )
          {
            if (att.getAttributeValues().isEmpty())
            {
              continue;
            }
            XMLObject attributeValue = att.getAttributeValues().get(0); // IN EIDAS there is just one value
                                                                        // except familyname!
            Element domElement = attributeValue.getDOM();
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

            EidasAttribute eidasAttribute = personAttributes.getInstance();
            if (eidasAttribute instanceof AbstractNonLatinScriptAttribute)
            {
              AbstractNonLatinScriptAttribute abstractAttribute = (AbstractNonLatinScriptAttribute)eidasAttribute;
              abstractAttribute.setLatinScript(att.getAttributeValues().get(0).getDOM().getTextContent());
              if (att.getAttributeValues().size() == 2)
              {
                abstractAttribute.setNonLatinScript(att.getAttributeValues()
                                                       .get(1)
                                                       .getDOM()
                                                       .getTextContent());
              }
            }
            else
            {
              eidasAttribute.setLatinScript(domElement.getTextContent());
            }


            eidasResp.attributes.add(eidasAttribute);

          }
        }
      }

      resp.getAssertions().clear();
      resp.getAssertions().addAll(assertions);
    }
    eidasResp.id = resp.getID();
    eidasResp.destination = resp.getDestination();
    eidasResp.inResponseTo = resp.getInResponseTo();
    eidasResp.issueInstant = Constants.format(resp.getIssueInstant().toDate());
    eidasResp.issuer = resp.getIssuer().getDOM().getTextContent();
    eidasResp.recipient = getAudience(resp);
    eidasResp.openSamlResp = resp;

    return eidasResp;
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
