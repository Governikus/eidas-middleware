/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.certrequest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Path;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.BOSHSMSimulatorService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import lombok.extern.slf4j.Slf4j;


/**
 * ASN.1 structure for Certificate Requests.
 *
 * @see CertificateRequestPath
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Slf4j
public class CertificateRequest extends AbstractASN1Encoder
{

  /**
   * Constructor.
   *
   * @param valueBytes value bytes of ASN.1
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(byte[])
   * @see CertificateRequestPath
   * @see CertificateRequestPath#getTag()
   * @see CertificateRequestPath#CV_CERTIFICATE
   */
  CertificateRequest(byte[] valueBytes) throws IOException
  {
    super(CertificateRequestPath.AUTHENTICATION.getTag().toByteArray(), valueBytes);
    check();
  }

  /**
   * Constructor.
   *
   * @param stream stream with ASN.1 bytes
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(InputStream, boolean)
   */
  public CertificateRequest(InputStream stream) throws IOException
  {
    super(stream);
    check();
  }

  private void check()
  {
    if (!CertificateRequestPath.AUTHENTICATION.getTag().equals(getDTag())
        && !CertificateRequestPath.CV_CERTIFICATE.getTag().equals(getDTag()))
    {
      throw new IllegalArgumentException("ASN.1 does not represent a certificate request");
    }
  }

  /** {@inheritDoc} */
  @Override
  public ASN1 getChildElementByPath(ASN1Path path) throws IOException
  {
    if (!(path instanceof CertificateRequestPath))
    {
      throw new IllegalArgumentException("only CertificateRequestPath permitted");
    }
    return super.getChildElementByPath(path);
  }

  /**
   * Gets part of request by path.
   *
   * @param path path to part
   * @return part of ASN.1 if found, otherwise <code>null</code>
   * @throws IOException if fails
   * @see ASN1#getChildElementByPath(ASN1Path)
   */
  ASN1 getRequestPart(CertificateRequestPath path) throws IOException
  {
    return super.getChildElementByPath(path);
  }

  /**
   * Signs certificate of request (mandatory).
   *
   * @param publicKey, <code>null</code> not permitted, must be instance of {@link OIDPublicKey}
   * @param alias alias of signature key, <code>null</code> or empty not permitted
   * @throws IOException
   * @throws IllegalArgumentException if any argument <code>null</code>, if publicKey not instance of
   *           {@link OIDPublicKey}
   * @throws UnsupportedOperationException
   * @throws HSMException
   * @throws InvalidKeySpecException
   * @throws SignatureException
   * @throws CertificateException
   * @throws KeyStoreException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws UnrecoverableKeyException
   */
  void signCVCBody(PublicKey publicKey, String alias) throws IOException, UnrecoverableKeyException,
    InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CertificateException,
    SignatureException, InvalidKeySpecException, HSMException
  {
    AssertUtil.notNull(publicKey, "public key");
    AssertUtil.notNullOrEmpty(alias, "alias");
    if (!(publicKey instanceof OIDPublicKey))
    {
      throw new IllegalArgumentException("only " + OIDPublicKey.class + " permitted");
    }

    this.setCVCPublicKey(publicKey);

    byte[] body = ByteUtil.copy(this.getChildElementByPath(CertificateRequestPath.CV_CERTIFICATE_BODY).getEncoded());

    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    byte[] signed = hsm.sign(alias, ((OIDPublicKey)publicKey).getOID(), body);
    this.setCVCSignature(signed);
  }

  /**
   * Sets public key.
   *
   * @param publicKey public key, <code>null</code> not permitted, must be instance of {@link OIDPublicKey}
   * @throws UnsupportedOperationException
   * @throws IOException
   * @throws IllegalArgumentException if publicKey <code>null</code> or not instance of {@link OIDPublicKey}
   */
  private void setCVCPublicKey(PublicKey publicKey) throws IOException
  {
    AssertUtil.notNull(publicKey, "public key");
    if (!(publicKey instanceof OIDPublicKey))
    {
      throw new IllegalArgumentException("only " + OIDPublicKey.class + " permitted");
    }
    this.getChildElementByPath(CertificateRequestPath.CV_CERTIFICATE_BODY)
        .replaceChildElement(this.getChildElementByPath(CertificateRequestPath.PUBLIC_KEY),
                             new ASN1(((OIDPublicKey)publicKey).getEncodedWithOID()),
                             this);
  }

  /**
   * Sets inner (mandatory) signature.
   *
   * @param signature signature as byte-array, <code>null</code> or empty not permitted
   * @throws UnsupportedOperationException
   * @throws IOException
   * @throws IllegalArgumentException if signature <code>null</code> or empty
   */
  private void setCVCSignature(byte[] signature) throws IOException
  {
    AssertUtil.notNullOrEmpty(signature, "signature");
    this.getChildElementByPath(CertificateRequestPath.CV_CERTIFICATE)
        .removeChildElement(this.getChildElementByPath(CertificateRequestPath.SIGNATURE), this);
    this.getChildElementByPath(CertificateRequestPath.CV_CERTIFICATE)
        .addChildElement(new ASN1(CertificateRequestPath.SIGNATURE.getTag().toByteArray(), signature), this);
  }

  /**
   * Signs request (conditional outer signature). Note: call this only after outer CAR has been set.
   *
   * @param oldPrivKeyAlias alias of old certificate, <code>null</code> or empty not permitted
   * @param algOID OID of signature algorithm, <code>null</code> not permitted
   * @param useGivenKey flag indicating whether to use a key given as file instead of a key stored in HSM
   * @throws IOException
   * @throws UnsupportedOperationException
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   * @throws HSMException
   * @throws InvalidKeySpecException
   * @throws SignatureException
   * @throws CertificateException
   * @throws KeyStoreException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws UnrecoverableKeyException
   */
  void signRequest(String oldPrivKeyAlias, OID algOID, boolean useGivenKey) throws IOException,
    UnrecoverableKeyException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
    KeyStoreException, CertificateException, SignatureException, InvalidKeySpecException, HSMException
  {
    AssertUtil.notNullOrEmpty(oldPrivKeyAlias, "alias of private key for signing");
    AssertUtil.notNull(algOID, "OID of signature algorithm");
    byte[] combinedBytes = null;
    for ( ASN1 asn1 : this.getChildElementList() )
    {
      combinedBytes = ByteUtil.combine(combinedBytes, asn1.getEncoded());
    }

    HSMService hsm = null;
    if (useGivenKey)
    {
      hsm = ServiceRegistry.Util.getServiceRegistry().getService(BOSHSMSimulatorService.class);
    }
    else
    {
      hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    }
    byte[] signed = hsm.sign(oldPrivKeyAlias, algOID, combinedBytes);
    this.setOuterSignature(signed);
  }

  /**
   * Sets outer signature.
   *
   * @param signature signature as byte-array, <code>null</code> or empty array not permitted
   * @throws IOException
   * @throws UnsupportedOperationException
   * @throws IllegalArgumentException
   */
  private void setOuterSignature(byte[] signature) throws IOException
  {
    AssertUtil.notNullOrEmpty(signature, "signature");
    this.removeChildElement(this.getChildElementByPath(CertificateRequestPath.OUTER_SIGNATURE), this);
    this.addChildElement(new ASN1(CertificateRequestPath.SIGNATURE.getTag().toByteArray(), signature), this);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized boolean isSequence()
  {
    return true;
  }

  public ECPublicKey getPublicKey() throws IOException
  {
    CertificateRequest cr = this;
    // if we have a CR without outer signature, we must create a full CR structure so that the getRequestPart method can
    // work correctly
    if (CertificateRequestPath.CV_CERTIFICATE.getTag().equals(getDTag()))
    {
      cr = new CertificateRequest(this.getEncoded());
    }

    try
    {
      return new ECPublicKey(cr.getRequestPart(CertificateRequestPath.PUBLIC_KEY).getEncoded());
    }
    catch (NullPointerException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to create ECPublicKey", e);
      }
      return null;
    }
  }

  public String getHolderReferenceString() throws IOException
  {
    CertificateRequest cr = this;
    // if we have a CR without outer signature, we must create a full CR structure so that the getRequestPart method can
    // work correctly
    if (CertificateRequestPath.CV_CERTIFICATE.getTag().equals(getDTag()))
    {
      cr = new CertificateRequest(this.getEncoded());
    }

    try
    {
      return new String(cr.getRequestPart(CertificateRequestPath.HOLDER_REFERENCE).getValue(), StandardCharsets.UTF_8);
    }
    catch (NullPointerException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to get holder reference string", e);
      }
      return null;
    }
  }

  public String getOuterAuthorityReferenceString() throws IOException
  {
    if (CertificateRequestPath.CV_CERTIFICATE.getTag().equals(getDTag()))
    {
      return null;
    }

    try
    {
      return new String(this.getRequestPart(CertificateRequestPath.OUTER_CA_REFERENCE).getValue(),
                        StandardCharsets.UTF_8);
    }
    catch (NullPointerException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to get outer authority reference string", e);
      }
      return null;
    }
  }
}
