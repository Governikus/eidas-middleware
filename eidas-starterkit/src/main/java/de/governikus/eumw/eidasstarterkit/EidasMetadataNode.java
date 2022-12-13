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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2alg.impl.DigestMethodBuilder;
import org.opensaml.saml.ext.saml2alg.impl.SigningMethodBuilder;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Company;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.GivenName;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SurName;
import org.opensaml.saml.saml2.metadata.TelephoneNumber;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.CompanyBuilder;
import org.opensaml.saml.saml2.metadata.impl.ContactPersonBuilder;
import org.opensaml.saml.saml2.metadata.impl.EmailAddressBuilder;
import org.opensaml.saml.saml2.metadata.impl.EncryptionMethodBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.metadata.impl.GivenNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationDisplayNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationURLBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SurNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.TelephoneNumberBuilder;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLConstants;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.litsec.eidas.opensaml.common.EidasConstants;
import se.litsec.eidas.opensaml.ext.SPType;
import se.litsec.eidas.opensaml.ext.SPTypeEnumeration;
import se.litsec.eidas.opensaml.ext.impl.SPTypeBuilder;


/**
 * Use this class to build a eu connector metadata.xml
 *
 * @author hohnholt
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Setter
public class EidasMetadataNode
{

  private String id;

  private String entityId;

  private Instant validUntil;

  private X509Certificate sigCert;

  private X509Certificate encCert;

  private EidasOrganisation organisation;

  private EidasContactPerson technicalContact;

  private EidasContactPerson supportContact;

  private String postEndpoint;

  private SPTypeEnumeration spType;

  private Boolean checkedAsValid;

  @Getter(AccessLevel.NONE)
  @Setter(AccessLevel.NONE)
  private List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();

  EidasMetadataNode(String id,
                    String entityId,
                    Instant validUntil,
                    X509Certificate sigCert,
                    X509Certificate encCert,
                    EidasOrganisation organisation,
                    EidasContactPerson technicalContact,
                    EidasContactPerson supportContact,
                    String postEndpoint,
                    SPTypeEnumeration spType,
                    List<EidasNameIdType> supportedNameIdTypes)
  {
    super();
    this.id = id;
    this.entityId = entityId;
    this.validUntil = validUntil;
    this.sigCert = sigCert;
    this.encCert = encCert;
    this.organisation = organisation;
    this.technicalContact = technicalContact;
    this.supportContact = supportContact;
    this.postEndpoint = postEndpoint;
    this.spType = spType;

    this.supportedNameIdTypes = supportedNameIdTypes;
    if (this.supportedNameIdTypes == null)
    {
      this.supportedNameIdTypes = new ArrayList<>();
    }
    if (this.supportedNameIdTypes.isEmpty())
    {
      this.supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    }
  }

  byte[] generate(EidasSigner signer) throws CertificateEncodingException, MarshallingException,
    SignatureException, TransformerException, IOException
  {
    EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
    entityDescriptor.getNamespaceManager()
                    .registerNamespaceDeclaration(new Namespace(EidasConstants.EIDAS_NS,
                                                                EidasConstants.EIDAS_PREFIX));
    entityDescriptor.getNamespaceManager()
                    .registerNamespaceDeclaration(new Namespace(SAMLConstants.SAML20ALG_NS,
                                                                SAMLConstants.SAML20ALG_PREFIX));
    entityDescriptor.getNamespaceManager()
                    .registerNamespaceDeclaration(new Namespace(XMLConstants.XSD_NS,
                                                                XMLConstants.XSD_PREFIX));
    entityDescriptor.getNamespaceManager()
                    .registerNamespaceDeclaration(new Namespace(XMLConstants.XSI_NS,
                                                                XMLConstants.XSI_PREFIX));
    entityDescriptor.setID(id);
    entityDescriptor.setEntityID(entityId);
    entityDescriptor.setValidUntil(validUntil);

    SPSSODescriptor spDescriptor = new SPSSODescriptorBuilder().buildObject();
    spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    spDescriptor.setWantAssertionsSigned(Boolean.FALSE);
    spDescriptor.setAuthnRequestsSigned(Boolean.TRUE);

    KeyDescriptor kd = new KeyDescriptorBuilder().buildObject();
    kd.setUse(UsageType.SIGNING);
    KeyInfo ki = new KeyInfoBuilder().buildObject();
    X509Data x509 = new X509DataBuilder().buildObject();
    org.opensaml.xmlsec.signature.X509Certificate x509Cert = new X509CertificateBuilder().buildObject();
    x509Cert.setValue(new String(Base64.getEncoder().encode(sigCert.getEncoded()), StandardCharsets.UTF_8));
    x509.getX509Certificates().add(x509Cert);
    ki.getX509Datas().add(x509);
    kd.setKeyInfo(ki);
    spDescriptor.getKeyDescriptors().add(kd);

    kd = new KeyDescriptorBuilder().buildObject();
    kd.setUse(UsageType.ENCRYPTION);
    ki = new KeyInfoBuilder().buildObject();
    x509 = new X509DataBuilder().buildObject();
    x509Cert = new X509CertificateBuilder().buildObject();
    x509Cert.setValue(new String(Base64.getEncoder().encode(encCert.getEncoded()), StandardCharsets.UTF_8));
    x509.getX509Certificates().add(x509Cert);
    ki.getX509Datas().add(x509);
    kd.setKeyInfo(ki);
    EncryptionMethod encMethod = new EncryptionMethodBuilder().buildObject();
    encMethod.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
    kd.getEncryptionMethods().add(encMethod);
    spDescriptor.getKeyDescriptors().add(kd);

    AssertionConsumerService acs = new AssertionConsumerServiceBuilder().buildObject();
    acs.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    acs.setLocation(postEndpoint);
    acs.setIndex(1);
    acs.setIsDefault(Boolean.TRUE);
    spDescriptor.getAssertionConsumerServices().add(acs);

    for ( EidasNameIdType nameIDType : this.supportedNameIdTypes )
    {
      NameIDFormat nif = new NameIDFormatBuilder().buildObject();
      nif.setURI(nameIDType.getValue());
      spDescriptor.getNameIDFormats().add(nif);
    }

    entityDescriptor.getRoleDescriptors().add(spDescriptor);

    Organization organization = new OrganizationBuilder().buildObject();
    OrganizationDisplayName odn = new OrganizationDisplayNameBuilder().buildObject();
    odn.setValue(organisation.getDisplayName());
    odn.setXMLLang(organisation.getLangId());
    organization.getDisplayNames().add(odn);
    OrganizationName on = new OrganizationNameBuilder().buildObject();
    on.setValue(organisation.getName());
    on.setXMLLang(organisation.getLangId());
    organization.getOrganizationNames().add(on);
    OrganizationURL ourl = new OrganizationURLBuilder().buildObject();
    ourl.setURI(organisation.getUrl());
    ourl.setXMLLang(organisation.getLangId());
    organization.getURLs().add(ourl);
    entityDescriptor.setOrganization(organization);

    ContactPerson cp = new ContactPersonBuilder().buildObject();
    Company comp = new CompanyBuilder().buildObject();
    comp.setValue(technicalContact.getCompany());
    cp.setCompany(comp);
    GivenName gn = new GivenNameBuilder().buildObject();
    gn.setValue(technicalContact.getGivenName());
    cp.setGivenName(gn);
    SurName sn = new SurNameBuilder().buildObject();
    sn.setValue(technicalContact.getSurName());
    cp.setSurName(sn);
    EmailAddress email = new EmailAddressBuilder().buildObject();
    email.setURI(technicalContact.getEmail());
    cp.getEmailAddresses().add(email);
    TelephoneNumber tel = new TelephoneNumberBuilder().buildObject();
    tel.setValue(technicalContact.getTel());
    cp.getTelephoneNumbers().add(tel);
    cp.setType(ContactPersonTypeEnumeration.TECHNICAL);
    entityDescriptor.getContactPersons().add(cp);

    cp = new ContactPersonBuilder().buildObject();
    comp = new CompanyBuilder().buildObject();
    comp.setValue(supportContact.getCompany());
    cp.setCompany(comp);
    gn = new GivenNameBuilder().buildObject();
    gn.setValue(supportContact.getGivenName());
    cp.setGivenName(gn);
    sn = new SurNameBuilder().buildObject();
    sn.setValue(supportContact.getSurName());
    cp.setSurName(sn);
    email = new EmailAddressBuilder().buildObject();
    email.setURI(supportContact.getEmail());
    cp.getEmailAddresses().add(email);
    tel = new TelephoneNumberBuilder().buildObject();
    tel.setValue(supportContact.getTel());
    cp.getTelephoneNumbers().add(tel);
    cp.setType(ContactPersonTypeEnumeration.SUPPORT);
    entityDescriptor.getContactPersons().add(cp);

    Extensions ext = new ExtensionsBuilder().buildObject();

    DigestMethod dm = new DigestMethodBuilder().buildObject();
    dm.setAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    ext.getUnknownXMLObjects().add(dm);

    SigningMethod sm = new SigningMethodBuilder().buildObject();
    sm.setAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    sm.setMinKeySize(256);
    ext.getUnknownXMLObjects().add(sm);

    if (spType != null)
    {
      SPType spTypeInt = new SPTypeBuilder().buildObject();
      spTypeInt.setType(spType);
      ext.getUnknownXMLObjects().add(spTypeInt);
    }

    sm = new SigningMethodBuilder().buildObject();
    sm.setAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
    sm.setMinKeySize(3072);
    sm.setMaxKeySize(4096);
    ext.getUnknownXMLObjects().add(sm);

    entityDescriptor.setExtensions(ext);

    byte[] result = null;
    List<Signature> sigs = new ArrayList<>();

    XMLSignatureHandler.addSignature(entityDescriptor,
                                     signer.getSigKey(),
                                     signer.getSigCert(),
                                     signer.getSigType(),
                                     signer.getSigDigestAlg());
    sigs.add(entityDescriptor.getSignature());

    EntityDescriptorMarshaller arm = new EntityDescriptorMarshaller();
    Element all = arm.marshall(entityDescriptor);
    if (!sigs.isEmpty())
    {
      Signer.signObjects(sigs);
    }

    Transformer trans = Utils.getTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      result = bout.toByteArray();
    }
    return result;
  }

  /**
   * Parse metadata.
   *
   * @param is stream containing metadata
   * @param signer verification certificate (optional)
   * @param continueOnInvalidSig <code>true</code> for allowing to continue on failed signature validation,
   *          <code>false</code> otherwise
   * @return
   * @throws XMLParserException
   * @throws UnmarshallingException
   * @throws CertificateException
   * @throws IOException
   * @throws ErrorCodeException
   * @throws DOMException
   * @throws ComponentInitializationException
   */
  static EidasMetadataNode parse(InputStream is, X509Certificate signer, boolean continueOnInvalidSig)
    throws XMLParserException, UnmarshallingException, CertificateException, ErrorCodeException,
    ComponentInitializationException
  {
    EidasMetadataNode eidasMetadataNode = new EidasMetadataNode();
    BasicParserPool ppMgr = Utils.getBasicParserPool();
    Document inCommonMDDoc = ppMgr.parse(is);
    Element metadataRoot = inCommonMDDoc.getDocumentElement();
    UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
    EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);

    Signature sig = metaData.getSignature();
    if (sig == null)
    {
      // with this implementation, unsigned metadata is accepted as before
      log.debug("No signature found on metadata");
      eidasMetadataNode.setCheckedAsValid(null);
    }
    else
    {
      try
      {
        XMLSignatureHandler.checkSignature(sig, signer);
        log.debug("Signature on metadata successfully validated");
        eidasMetadataNode.setCheckedAsValid(Boolean.TRUE);
      }
      catch (ErrorCodeException e)
      {
        if (!continueOnInvalidSig)
        {
          log.debug("Signature on metadata not validated, not accepting this metadata");
          throw e;
        }
        log.debug("Signature on metadata not validated, but continue as requested");
        eidasMetadataNode.setCheckedAsValid(Boolean.FALSE);
      }
    }

    eidasMetadataNode.setId(metaData.getID());
    eidasMetadataNode.setEntityId(metaData.getEntityID());
    eidasMetadataNode.setValidUntil(metaData.getValidUntil() == null ? null : metaData.getValidUntil());
    if (metaData.getExtensions() != null)
    {
      Element extension = metaData.getExtensions().getDOM();
      for ( int i = 0 ; i < extension.getChildNodes().getLength() ; i++ )
      {
        Node n = extension.getChildNodes().item(i);
        if (SPType.DEFAULT_ELEMENT_LOCAL_NAME.equals(n.getLocalName()))
        {
          eidasMetadataNode.spType = SPTypeHelper.getSPTypeFromString(n.getTextContent());
          break;
        }
      }
    }

    SPSSODescriptor ssoDescriptor = metaData.getSPSSODescriptor(SAMLConstants.SAML20P_NS);

    ssoDescriptor.getAssertionConsumerServices().forEach(s -> {
      String bindString = s.getBinding();
      if (SAMLConstants.SAML2_POST_BINDING_URI.equals(bindString))
      {
        eidasMetadataNode.setPostEndpoint(s.getLocation());
      }
    });

    for ( KeyDescriptor k : ssoDescriptor.getKeyDescriptors() )
    {
      if (k.getUse() == UsageType.ENCRYPTION)
      {
        eidasMetadataNode.encCert = EidasMetadataService.getFirstCertFromKeyDescriptor(k);
      }
      else if (k.getUse() == UsageType.SIGNING)
      {
        eidasMetadataNode.sigCert = EidasMetadataService.getFirstCertFromKeyDescriptor(k);
      }
    }
    return eidasMetadataNode;
  }
}
