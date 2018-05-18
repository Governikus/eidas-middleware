/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback.CertificateValidationException;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback.CertificateValidator;
import com.sun.xml.wss.impl.callback.SignatureKeyCallback;
import com.sun.xml.wss.impl.callback.SignatureVerificationKeyCallback;
import com.sun.xml.wss.impl.callback.SignatureVerificationKeyCallback.PublicKeyBasedRequest;
import com.sun.xml.wss.impl.callback.SignatureVerificationKeyCallback.Request;
import com.sun.xml.wss.impl.callback.SignatureVerificationKeyCallback.X509IssuerSerialBasedRequest;
import com.sun.xml.wss.impl.callback.SignatureVerificationKeyCallback.X509SubjectKeyIdentifierBasedRequest;
import com.sun.xml.wss.impl.misc.DefaultCallbackHandler;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;


/**
 * This class can handle all occurring callbacks and is backed up by the Identity Managers configuration and
 * classes.
 * 
 * @author tt
 */
public class EidCallbackHandler implements CallbackHandler
{

  private static final Log LOG = LogFactory.getLog(EidCallbackHandler.class);

  private final CallbackHandler defaultCallbackHandler;

  /**
   * Create instance and get default callback handler top delegate calls to.
   * 
   * @throws XWSSecurityException
   */
  public EidCallbackHandler() throws XWSSecurityException
  {
    defaultCallbackHandler = new DefaultCallbackHandler("server", null);
  }

  /**
   * Always return true.
   */
  public static class NullCertificateValidator implements CertificateValidator
  {

    /**
     * Always return true. We do an explicit check against a list of allowed certificates so this validation
     * is not needed.
     */
    @Override
    public boolean validate(X509Certificate cert) throws CertificateValidationException
    {
      return true;
    }

  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
  {
    for ( Callback c : callbacks )
    {
      if (c instanceof SignatureKeyCallback)
      {
        handleSignatureKeyCallback((SignatureKeyCallback)c);
      }
      else if (c instanceof SignatureVerificationKeyCallback)
      {
        handleSignatureVerificationKeyCallback((SignatureVerificationKeyCallback)c);
      }
      else if (c instanceof CertificateValidationCallback)
      {
        ((CertificateValidationCallback)c).setValidator(new NullCertificateValidator());
      }
      else
      {
        LOG.debug("delegating callback of class " + c.getClass().getName());
        defaultCallbackHandler.handle(new Callback[]{c});
      }
    }
  }

  private void handleSignatureVerificationKeyCallback(SignatureVerificationKeyCallback c)
    throws UnsupportedCallbackException, IOException
  {
    String msg = null;
    Request request = c.getRequest();
    if (request instanceof X509IssuerSerialBasedRequest)
    {
      msg = handleIssuerSerialBasedRequest((X509IssuerSerialBasedRequest)request);
      if (msg == null)
      {
        return;
      }
    }
    if (request instanceof X509SubjectKeyIdentifierBasedRequest)
    {
      msg = handleSubjectKeyIdentifierBasedRequest((X509SubjectKeyIdentifierBasedRequest)request);
      if (msg == null)
      {
        return;
      }
    }
    if (request instanceof PublicKeyBasedRequest)
    {
      msg = handlePublicKeyBasedRequest((PublicKeyBasedRequest)request);
      if (msg == null)
      {
        return;
      }
    }
    if (msg == null)
    {
      unsupportedRequest("handleSignatureVerificationKeyCallback", request);
    }
    else
    {
      throw new IOException(msg);
    }
  }

  private String handlePublicKeyBasedRequest(PublicKeyBasedRequest pubKeyReq) throws IOException
  {
    PublicKey pubKey = pubKeyReq.getPublicKey();
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto provider = config.findProviderForPublicKey(pubKey);
    if (provider != null)
    {
      Boolean firstCert = config.usesFirstCertForPublicKey(pubKey);
      if (firstCert != null && firstCert)
      {
        pubKeyReq.setX509Certificate(provider.getSignatureCert());
        return null;
      }
      if (firstCert != null)
      {
        pubKeyReq.setX509Certificate(provider.getSignatureCert2());
        return null;
      }
      // should never happen
      throw new IOException("inconsistent results from calls to findProviderForPublicKey() and usesFirstCertForPublicKey()");
    }
    String msg = "no provider has specified public key: " + pubKey;
    LOG.warn(msg);
    return msg;
  }

  private String handleSubjectKeyIdentifierBasedRequest(X509SubjectKeyIdentifierBasedRequest kiReq)
    throws IOException
  {
    byte[] identifier = kiReq.getSubjectKeyIdentifier();
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto provider = config.findProviderForCertificate(identifier);
    if (provider != null)
    {
      Boolean firstCert = config.usesFirstCertForCertificate(identifier);
      if (firstCert != null && firstCert)
      {
        kiReq.setX509Certificate(provider.getSignatureCert());
        return null;
      }
      if (firstCert != null)
      {
        kiReq.setX509Certificate(provider.getSignatureCert2());
        return null;
      }
      // should never happen
      throw new IOException("inconsistent results from calls to findProviderForCertificate() and usesFirstCertForCertificate()");
    }
    String msg = "no provider has specified signature certificate for identifier: "
          + DatatypeConverter.printBase64Binary(identifier);
    LOG.warn(msg);
    return msg;
  }

  private String handleIssuerSerialBasedRequest(X509IssuerSerialBasedRequest issuerSerialRequest) throws IOException
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto provider = config.findProviderForCertificate(issuerSerialRequest.getIssuerName(),
                                                                    issuerSerialRequest.getSerialNumber());
    if (provider != null)
    {
      Boolean firstCert = config.usesFirstCertForCertificate(issuerSerialRequest.getIssuerName(),
                                                             issuerSerialRequest.getSerialNumber());
      if (firstCert != null && firstCert)
      {
        issuerSerialRequest.setX509Certificate(provider.getSignatureCert());
        return null;
      }
      if (firstCert != null)
      {
        issuerSerialRequest.setX509Certificate(provider.getSignatureCert2());
        return null;
      }
      // should never happen
      throw new IOException("inconsistent results from calls to findProviderForCertificate() and usesFirstCertForCertificate()");
    }
    String msg = "no provider has specified signature certificate for IssuerName: "
          + issuerSerialRequest.getIssuerName() + ", SerialNumber: " + issuerSerialRequest.getSerialNumber();
    LOG.warn(msg);
    return msg;
  }

  /**
   * The signature key is always the same in this server.
   * 
   * @param callback
   * @throws UnsupportedCallbackException
   */
  private void handleSignatureKeyCallback(SignatureKeyCallback callback) throws UnsupportedCallbackException,
    IOException
  {
    SignatureKeyCallback.Request request = callback.getRequest();
    try
    {
      if (request instanceof SignatureKeyCallback.PrivKeyCertRequest)
      {
        SignatureKeyCallback.PrivKeyCertRequest keyCertRequest = (SignatureKeyCallback.PrivKeyCertRequest)request;
        CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
        if (config == null || config.getSignatureCertWebService() == null
            || config.getSignatureKeyWebService() == null)
        {
          String msg = "No eID-WebService signature key configured in poseidas server";
          LOG.error(msg);
          throw new IOException(msg);
        }
        keyCertRequest.setX509Certificate(Utils.convertToSun(config.getSignatureCertWebService()));
        keyCertRequest.setPrivateKey(config.getSignatureKeyWebService());
        return;
      }
      if (request instanceof SignatureKeyCallback.DefaultPrivKeyCertRequest)
      {
        SignatureKeyCallback.DefaultPrivKeyCertRequest keyCertRequest = (SignatureKeyCallback.DefaultPrivKeyCertRequest)request;
        CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
        if (config == null || config.getSignatureCertWebService() == null
            || config.getSignatureKeyWebService() == null)
        {
          String msg = "No eID-WebService signature key configured in poseidas server";
          LOG.error(msg);
          throw new IOException(msg);
        }
        keyCertRequest.setX509Certificate(Utils.convertToSun(config.getSignatureCertWebService()));
        keyCertRequest.setPrivateKey(config.getSignatureKeyWebService());
        return;
      }
    }
    catch (CertificateException | NoSuchProviderException e)
    {
      String msg = "can not convert certificate to Sun cert";
      LOG.error(msg);
      throw new IOException(msg, e);
    }
    unsupportedRequest("handleSignatureKeyCallback", request);
  }


  private void unsupportedRequest(String method, Object req) throws UnsupportedCallbackException
  {
    LOG.error(method + "() request not supported. Please implement " + req.getClass().getName());
    throw new UnsupportedCallbackException(null, "Request not supported. Please implement: "
                                                 + req.getClass().getName());
  }
}
