package de.governikus.eumw.eidasmiddleware.handler;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import jakarta.xml.bind.DatatypeConverter;

import org.opensaml.core.xml.Namespace;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import se.swedenconnect.opensaml.eidas.common.EidasConstants;


@UtilityClass
public class RequestHelper {

  @SneakyThrows
  public static byte[] createSamlPostRequest(String destination,
                                             String providerName,
                                             X509Certificate cert,
                                             PrivateKey key,
                                             String signatureAlgorithm,
                                             String digestAlgorithm) {
    AuthnRequest authnRequest = createUnsignedAuthnRequest(destination, providerName);

    Signature sig = new SignatureBuilder().buildObject();
    BasicX509Credential credential = new BasicX509Credential(cert);
    credential.setPrivateKey(key);
    sig.setSigningCredential(credential);
    sig.setSignatureAlgorithm(signatureAlgorithm);
    sig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
    X509Data x509Data = new X509DataBuilder().buildObject();
    org.opensaml.xmlsec.signature.X509Certificate xmlcert = new X509CertificateBuilder().buildObject();
    xmlcert.setValue(DatatypeConverter.printBase64Binary(cert.getEncoded()));
    x509Data.getX509Certificates().add(xmlcert);
    keyInfo.getX509Datas().add(x509Data);
    sig.setKeyInfo(keyInfo);
    authnRequest.setSignature(sig);
    ((SAMLObjectContentReference) sig.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);


    List<Signature> sigs = new ArrayList<>();
    sigs.add(authnRequest.getSignature());
    AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
    Element all = arm.marshall(authnRequest);
    Signer.signObjects(sigs);

    return marshallAuthnRequest(all);
  }

  @SneakyThrows
  public static byte[] marshallAuthnRequest(Element all) {
    Transformer trans = Utils.getTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      return bout.toByteArray();
    }
  }

  @SneakyThrows
  public static AuthnRequest createUnsignedAuthnRequest(String destination, String providerName) {
    EidasSaml.init();

    AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

    authnRequest.setID("_" + UUID.randomUUID());
    authnRequest.setForceAuthn(true);
    authnRequest.setIsPassive(false);
    authnRequest.getNamespaceManager()
            .registerNamespaceDeclaration(new Namespace(EidasConstants.EIDAS_NS, EidasConstants.EIDAS_PREFIX));
    authnRequest.setDestination(destination);
    authnRequest.setIssueInstant(Instant.now());
    authnRequest.setProviderName(providerName);
    return authnRequest;
  }
}
