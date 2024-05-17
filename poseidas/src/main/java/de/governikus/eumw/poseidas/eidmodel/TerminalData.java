/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidmodel;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKeyPath;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECMath;
import de.governikus.eumw.poseidas.cardbase.crypto.ec.ECUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandler;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandlerFactory;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDSequence.Authorizations;


/**
 * <p>
 * Descriptor of the Terminal Rights, all the information needed to communicate with remote eID card. Contains
 * CVC, description and sector public key for a terminal certificate
 * </p>
 *
 * @author Alexander Funk
 * @author <a href="mail:obe@bos-bremen.de">Ole Behrens</a>
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 */
public class TerminalData
{

  /**
   * Logger for CVC data
   */
  private static final Log LOG = LogFactory.getLog(TerminalData.class.getName());


  /**
   * CVC description if existing
   */
  private CertificateDescription cvcDescription;

  private final byte[] cvcDescriptionBytes;

  /**
   * Inner wrapper for CVC bytes
   */
  private final ECCVCertificate cvcWrapper;

  /**
   * Private key for this CVC
   */
  private byte[] pkcs8PrivateKeyBytes;

  /**
   * Restricted identification
   */
  private byte[] riKeyIBytes;

  /**
   * Pseudonymous signature.
   */
  private byte[] psKeyBytes;

  /**
   * CVC for the EAC1 data
   *
   * @param cvcWrapper a cvcWrapper Object that contains a previously parsed CVC
   * @param cvcDescriptionBytes a byte array as CVC description encoded in ASN1
   * @param pkcs8PrivateKeyBytes a byte array as private key encoded in ASN1 may be null for client side use
   * @param riKeyIBytes the RestrictedID Key 1 to authenticate by a restricted ID may be null
   * @param psKeyBytes the Pseudonymous Signature Key to may be null
   * @throws IllegalArgumentException if one of the input parameter is malformed or can not be read or the CVC
   *           does not match the cvcDescription.
   */
  private TerminalData(ECCVCertificate cvcWrapper,
                       byte[] cvcDescriptionBytes,
                       byte[] pkcs8PrivateKeyBytes,
                       byte[] riKeyIBytes,
                       byte[] psKeyBytes)
  {
    // Check if the CVC wrapper is available
    if (cvcWrapper == null)
    {
      throw new IllegalArgumentException("CVC wrapper for CVC object not set");
    }
    else
    {
      this.cvcWrapper = cvcWrapper;
    }

    this.cvcDescriptionBytes = cvcDescriptionBytes;
    // Set the description
    if (cvcDescriptionBytes != null && cvcDescriptionBytes.length > 0)
    {
      // Try to get description object and check against the CVC bytes
      try
      {
        cvcDescription = new CertificateDescription(cvcDescriptionBytes);
        if (!cvcWrapper.checkCVCDescriptionHash(cvcDescription))
        {
          throw new IllegalArgumentException("Description does not match the terminal certificate: "
                                             + cvcDescription);
        }
      }
      catch (IOException e)
      {
        String message = "Unable to create CVC description object";
        LOG.debug(message, e);
        throw new IllegalArgumentException(message, e);
      }
    }

    // Set the private key
    if (pkcs8PrivateKeyBytes != null && pkcs8PrivateKeyBytes.length > 0)
    {
      this.pkcs8PrivateKeyBytes = pkcs8PrivateKeyBytes.clone();
    }

    if (riKeyIBytes != null && riKeyIBytes.length > 0)
    {
      this.riKeyIBytes = riKeyIBytes.clone();
    }

    if (psKeyBytes != null && psKeyBytes.length > 0)
    {
      this.psKeyBytes = psKeyBytes.clone();
    }

  }

  /**
   * Creates a Terminal Descriptor with a Card verifiable Certificate and some other informations.
   *
   * @param cvcBytes a byte array as CVC encoded in ASN1
   * @param cvcDescriptionBytes a byte array as CVC description encoded in ASN1
   * @param pkcs8PrivateKeyBytes a byte array as private key encoded in ASN1 may be null for client side use
   * @param riKeyIBytes the RestrictedID Key 1 to authenticate by a restricted ID may be null
   * @param psKeyBytes the Pseudonymous Signature Key to may be null
   * @throws IllegalArgumentException if one of the input parameter is malformed or can not be read or the CVC
   *           does not match the cvcDescription.
   */
  public TerminalData(byte[] cvcBytes,
                      byte[] cvcDescriptionBytes,
                      byte[] pkcs8PrivateKeyBytes,
                      byte[] riKeyIBytes,
                      byte[] psKeyBytes)
    throws IOException
  {
    this(new ECCVCertificate(cvcBytes), cvcDescriptionBytes, pkcs8PrivateKeyBytes, riKeyIBytes, psKeyBytes);
  }

  /**
   * Creates a Terminal Descriptor with a CVC
   *
   * @param cvcBytes ASN1 encoded CVC to be set
   * @param cvcDescriptionBytes ASN1 encoded description for the CVC
   * @throws IllegalArgumentException if one of the input parameter is malformed or the CVC does not match the
   *           description set
   */
  public TerminalData(byte[] cvcBytes, byte[] cvcDescriptionBytes) throws IOException
  {
    this(cvcBytes, cvcDescriptionBytes, null, null, null);
  }

  /**
   * Creates a simple CVC only by byte array. Description is not checked
   *
   * @param cvcBytes ASN1 encoded CVC to be set
   */
  public TerminalData(byte[] cvcBytes) throws IOException
  {
    this(cvcBytes, null, null, null, null);
  }


  /**
   * Gets the expiration date of the certificate as a java date object. The returned date is the moment from which a CVC
   * can no longer be used.
   *
   * @return the expiration date of the certificate as Date object
   */
  public Date getExpirationDate()
  {
    return cvcWrapper.getExpirationDateDate();
  }

  /**
   * gets the effective date of the certificate as a java date object
   *
   * @return the effective date of the certificate as Date object
   */
  public Date getEffectiveDate()
  {
    return cvcWrapper.getEffectiveDateDate();
  }

  /**
   * gets the CVC Description
   *
   * @return the CVC Description
   */
  public CertificateDescription getCVCDescription()
  {
    return cvcDescription;
  }

  /**
   * gets the Card Holder Authentication Template
   *
   * @return the Card Holder Authentication Template
   */
  public CertificateHolderAuthorizationTemplate getCHAT()
  {
    return cvcWrapper.getChat();
  }

  public Authorizations getAuthorizations()
  {
    return new Authorizations(this.cvcWrapper.getChat());
  }

  /**
   * @return the private key or null
   */
  public byte[] getPrivateKey()
  {
    return pkcs8PrivateKeyBytes == null ? null : pkcs8PrivateKeyBytes.clone();
  }

  /**
   * Get the public key ANS1 representation from CVC bytes
   *
   * @return public key as ASN1
   * @throws IOException if read on CVC fails
   */
  public de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey getPublicKey() throws IOException
  {
    return cvcWrapper.getPublicKey();
  }

  /**
   * Get the signature bytes of this CVC
   *
   * @return byte array representing the signature
   * @throws IOException if read on CVC fails
   */
  public byte[] getSignatureBytes() throws IOException
  {
    return cvcWrapper.getChildElementByPath(ECCVCPath.SIGNATURE).getValue();
  }

  public byte[] getSectorPublicKeyHash()
  {
    return cvcWrapper.getSectorPublicKeyHash();
  }

  /**
   * Get the hash value of the description-hash set for this certificate
   *
   * @return the hash value for an enveloped description
   */
  public byte[] getDescriptionHashBytes()
  {
    try
    {
      return cvcWrapper.getChildElementByPath(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION_HASH)
                       .getValue();
    }
    catch (IOException e)
    {
      LOG.info("Cannot extract description from CVC: " + e.getMessage(), e);
      return new byte[]{};
    }
  }

  /**
   * Returns the service provider name from description
   *
   * @return name of service provider
   * @throws IOException if no description is available
   */
  public String getServiceProvider() throws IOException
  {
    if (containsCVCDescription())
    {
      return getCVCDescription().getSubjectName();
    }
    else
    {
      throw new IOException("Cannot return name of service provider:" + " Description is not available");
    }
  }

  /**
   * Try to parse the purpose from terms of usage
   *
   * @return purpose of description
   * @throws IOException if no description is available
   */
  public String getPurpose() throws IOException
  {
    if (containsCVCDescription())
    {
      String reference = "Siehe Details";
      String text = getCVCDescription().getTermsOfUsagePlainText();
      if (text != null)
      {
        String[] purposes = {"Gesch\u00e4ftszweck:", "Zweck des Auslesevorgangs:", "Verwendung der Daten:"};
        for ( String purpose : purposes )
        {
          if (text.contains(purpose))
          {
            text = text.substring(text.indexOf(purpose) + purpose.length());
            String[] texts = text.split("\r\n");
            if (texts.length < 2)
            {
              continue;
            }
            return texts[1];
          }
        }
      }
      return reference;
    }
    else
    {
      throw new IOException("Cannot return terms of usage text/purpose:" + " Description is not available");
    }
  }

  /**
   * A reference to the holder of the certificate
   *
   * @return a reference to the holder of the certificate
   */
  public byte[] getHolderReference()
  {
    try
    {
      return cvcWrapper.getChildElementByPath(ECCVCPath.HOLDER_REFERENCE).getValue();
    }
    catch (IOException e)
    {
      String message = "CVC bytes are malformed";
      LOG.error(message + ": " + e.getLocalizedMessage());
      throw new IllegalArgumentException(message, e);
    }
  }

  public String getHolderReferenceString()
  {
    return this.cvcWrapper.getHolderReferenceString();
  }

  /**
   * Reference to the certificate authority
   *
   * @return the CAReference
   */
  public byte[] getCAReference()
  {
    try
    {
      return cvcWrapper.getChildElementByPath(ECCVCPath.CA_REFERENCE).getValue();
    }
    catch (IOException e)
    {
      String message = "CVC bytes are malformed";
      LOG.error(message + ": " + e.getLocalizedMessage());
      throw new IllegalArgumentException(message, e);
    }
  }

  public String getCAReferenceString()
  {
    return this.cvcWrapper.getAuthorityReferenceString();
  }

  /**
   * Gets the RIKey
   *
   * @return the riKey may be null
   */
  public byte[] getRIKey1()
  {
    return riKeyIBytes == null ? null : riKeyIBytes.clone();
  }

  /**
   * Gets the PSKey
   *
   * @return the pskey may be null
   */
  public byte[] getPSKey()
  {
    return this.psKeyBytes == null ? null : this.psKeyBytes.clone();
  }

  /**
   * Returns the eService certificate
   *
   * @see CVCWrapper#getEncoded()
   * @return byte array representing the eService certificate
   */
  public byte[] getEncoded()
  {
    return cvcWrapper.getEncoded();
  }

  /**
   * Get the encoded body of this CVC
   *
   * @return CVC body
   * @throws IOException if read on CVC fails
   */
  public byte[] getEncodedBody() throws IOException
  {
    return cvcWrapper.getChildElementByPath(ECCVCPath.CV_CERTIFICATE_BODY).getEncoded();
  }

  /**
   * Indicates if this CVC contains a description
   *
   * @return true if description is set for this CVC
   */
  private boolean containsCVCDescription()
  {
    return cvcDescription != null;
  }

  /**
   * Verifies a complete list of certificates to this CVC. Chain should be sorted as followed if the terminal
   * CVC should be verified
   * <ul>
   * <li>DV Certificate</li>
   * <li>All involved Link Certificates</li>
   * <li>Root Certificate</li>
   * </ul>
   *
   * @param certificates representing the chain for verification
   * @return true if chain is valid
   * @throws IOException if input is invalid
   */
  public boolean verify(List<TerminalData> certificates) throws IOException
  {
    if (certificates == null)
    {
      throw new IOException("Cannot build chain: List is null");
    }
    else if (certificates.isEmpty() && !isSelfSigned())
    {
      throw new IOException("Cannot build chain: List is empty and CVC not self-signed");
    }
    else if (!certificates.get(certificates.size() - 1).isSelfSigned())
    {
      throw new IOException("Cannot verify certificate: No root certificate available");
    }
    else
    {
      List<TerminalData> reverse = new LinkedList<>();
      reverse.add(this);
      for ( TerminalData certificate : certificates )
      {
        reverse.add(0, certificate);
      }
      return verifyChain(reverse);
    }
  }

  /**
   * Verify every element of this chain
   *
   * @param certificates to be checked
   * @return true if list is valid
   */
  private boolean verifyChain(List<TerminalData> certificates)
  {
    // The list with all elements already checked
    List<TerminalData> validated = new LinkedList<>();
    for ( TerminalData certificate : certificates )
    {
      // Check if this element is valid
      if (certificate.verifyChainElement(validated))
      {
        // Add this element to list
        validated.add(0, certificate);
      }
      else
      {
        return false;
      }
    }
    return true;
  }

  /**
   * Verifies certificate against a chain
   *
   * @param verifiedCertificates already verified
   * @return true if certificate is valid
   */
  private boolean verifyChainElement(List<TerminalData> verifiedCertificates)
  {
    try
    {
      switch (verifiedCertificates.size())
      {

        case 0:
          // Indicates this is a root
          return verify();
        case 1:
          // Indicates certificate is the first certificate after the root
          return verify(verifiedCertificates.get(0));
        default:
          // Any certificate from list
          for ( TerminalData paramSpecCVC : verifiedCertificates )
          {
            // Try to find the latest parameter specification
            ECCVCertificate paramSpecCertificate = new ECCVCertificate(paramSpecCVC.getEncoded());
            ECParameterSpec paramSpec = null;
            try
            {
              paramSpec = ECUtil.parameterSpecFromCVC(paramSpecCertificate);
            }
            catch (NullPointerException e)
            {
              LOG.debug("Build Param Spec failed = Public key missing");
            }
            catch (IllegalArgumentException e)
            {
              LOG.debug("Build Param Spec failed for = " + paramSpecCVC.getHolderReferenceString());
            }
            catch (IOException e)
            {
              LOG.debug("No Param Spec available for = " + paramSpecCVC.getHolderReferenceString());
            }
            if (paramSpec != null)
            {
              return verify(verifiedCertificates.get(0), paramSpecCVC);
            }
          }
          return false;
      }
    }
    catch (Exception e)
    {
      LOG.debug("Fail to verify CVC element", e);
    }
    return false;
  }

  /**
   * Verifies a root certificate. Note that this verification works only for self-signed root certificates
   *
   * @return true if root certificate signature is valid
   * @throws IOException is thrown if required data cannot be provided for verification
   * @throws GeneralSecurityException if key material is not available and verification fails
   * @throws IllegalArgumentException if any illegal parameter was submitted
   */
  private boolean verify() throws IOException, GeneralSecurityException
  {
    return verify(this, this);
  }

  /**
   * Verifies a certificate against the signing certificate. Note that the signing certificate must hold the
   * latest parameter specification
   *
   * @param signingCVC that signed this CVC
   * @return true if verification returning positive result
   * @throws IOException is thrown if required data cannot be provided for verification
   * @throws GeneralSecurityException if key material is not available and verification fails
   * @throws IllegalArgumentException if any illegal parameter was submitted
   */
  private boolean verify(TerminalData signingCVC) throws IOException, GeneralSecurityException
  {
    if (signingCVC.isSelfSigned())
    {
      return verify(signingCVC, signingCVC);
    }
    else
    {
      throw new IllegalArgumentException("Signing CVC is not self signed");
    }
  }

  /**
   * Verifies a certificate against the signing certificate and a CVC holding the latest parameter
   * specification
   *
   * @param signingCVC that signed this CVC
   * @param paramSpecCVC holding the latest parameter specifications
   * @return true if verification returning positive result
   * @throws IOException is thrown if required data cannot be provided for verification
   * @throws GeneralSecurityException if key material is not available and verification fails
   * @throws IllegalArgumentException if any illegal parameter was submitted
   */
  private boolean verify(TerminalData signingCVC, TerminalData paramSpecCVC)
    throws IOException, GeneralSecurityException
  {
    if (signingCVC == null || paramSpecCVC == null)
    {
      throw new IllegalArgumentException("Certificate is null");
    }
    else if (!isSignedBy(signingCVC))
    {
      throw new IllegalArgumentException(getHolderReferenceString() + " not signed by "
                                         + signingCVC.getHolderReferenceString());
    }
    else
    {
      // Get the latest param specification from CVC
      ECCVCertificate paramSpecCertificate = new ECCVCertificate(paramSpecCVC.getEncoded());
      ECParameterSpec paramSpec = ECUtil.parameterSpecFromCVC(paramSpecCertificate);
      KeyHandler keyHandlerEC = KeyHandlerFactory.newKeyHandler("EC",
                                                                paramSpec.getCurve().getField().getFieldSize()
                                                                      / 8);
      // Get the public key from signing CVC
      de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKey publicKey = signingCVC.getPublicKey();
      ASN1 child = publicKey.getChildElementByPath(ECPublicKeyPath.PUBLIC_POINT_Y);
      ECPublicKey ecPublicKey = (ECPublicKey)keyHandlerEC.buildKeyFromBytes(paramSpec, child.getValue());
      // Get the OID for used hash algorithm
      OID oid = new OID(paramSpecCertificate.getChildElementByPath(ECCVCPath.PUBLIC_KEY_OID).getEncoded());
      String hashAlgo;
      if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1))
      {
        hashAlgo = "SHA-1";
      }
      else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224))
      {
        hashAlgo = "SHA-224";
      }
      else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256))
      {
        hashAlgo = "SHA-256";
      }
      else
      {
        throw new GeneralSecurityException("Unknown OID for hash algorithm");
      }
      return ECMath.verifySignature(getSignatureBytes(), getEncodedBody(), ecPublicKey, hashAlgo);
    }
  }

  /**
   * Indicates if this certificate seems to be self-signed
   *
   * @return true if is self-signed
   */
  public boolean isSelfSigned()
  {
    return Arrays.equals(getHolderReference(), getCAReference());
  }

  /**
   * Indicates if this CA reference is the given one. NOTE: This is no verification
   *
   * @param signerCVC to be checked as CA reference
   * @return true if references matching
   */
  private boolean isSignedBy(TerminalData signerCVC)
  {
    if (signerCVC == null)
    {
      return false;
    }
    else
    {
      return Arrays.equals(getCAReference(), signerCVC.getHolderReference());
    }
  }

  @Override
  public String toString()
  {
    StringBuilder stringBuilder = new StringBuilder("CVC");
    stringBuilder.append(" EFFECTIVE DATE = ")
                 .append(DateFormat.getDateInstance().format(getEffectiveDate()))
                 .append(" EXPIRATION DATE = ")
                 .append(DateFormat.getDateInstance().format(getExpirationDate()))
                 .append(" HOLDER REFERENCE = ")
                 .append(this.cvcWrapper.getHolderReferenceString())
                 .append(" CA REFERENCE = ")
                 .append(this.cvcWrapper.getAuthorityReferenceString());
    if (cvcDescription != null)
    {
      stringBuilder.append("\n CVC DESCRIPTION = ").append(cvcDescription);
    }
    return stringBuilder.toString();
  }

  /**
   * After session is read, session input is restored from inner implementation
   *
   * @param is for this session
   * @throws ClassNotFoundException
   * @throws IOException
   */
  private void readObject(ObjectInputStream is) throws IOException, ClassNotFoundException
  {
    is.defaultReadObject();
    if (cvcDescriptionBytes != null && cvcDescriptionBytes.length > 0)
    {
      cvcDescription = new CertificateDescription(cvcDescriptionBytes);
    }
  }
}
