/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.eac;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.SpringApplicationContextHelper;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardbase.crypto.HashConstants;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.SignedDataChecker;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.CmsSignatureChecker;
import lombok.extern.slf4j.Slf4j;


/**
 * Modified code from the mCard. Checks a reply from the EID process and verifies if the certificate used to sign the
 * travel document is a trustworthy one from the master list.
 *
 * @author Ole Behrens
 */
@Slf4j
public class EACSignedDataChecker extends EACSignedDataParser implements SignedDataChecker
{

  private final Set<String> allowedDocumentTypes;

  private final CmsSignatureChecker cmsSignatureChecker;

  /**
   * Instance needs master list
   *
   * @param masterList the master list of all trusted certificates
   * @param logPrefix
   */
  public EACSignedDataChecker(List<X509Certificate> masterList, String logPrefix)
  {
    super(logPrefix);
    //The allowed Digest Algorithms and Signature Algorithms can be found in TR-3116-2 2.1.2 (Status 2023)
    //The allowed elliptic curves can be found in TR-3116-2 1.4.2 (Status 2023)
    cmsSignatureChecker = new CmsSignatureChecker(masterList,
                                                  Set.of(HashConstants.SHA256_OID_STRING,
                                                         HashConstants.SHA384_OID_STRING,
                                                         HashConstants.SHA512_OID_STRING),
                                                  Set.of(OIDConstants.OID_ECDSA_SHA256.getOIDString(),
                                                         OIDConstants.OID_ECDSA_SHA384.getOIDString(),
                                                         OIDConstants.OID_ECDSA_SHA512.getOIDString()),
                                                  Set.of("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"));
    this.allowedDocumentTypes = getAllowedDocuments();
  }



  /** {@inheritDoc} */
  @Override
  public Certificate checkSignedData(byte[] data)
  {
    try
    {
      cmsSignatureChecker.checkEnvelopedSignature(data, CertificationRevocationListImpl.getInstance());
      log.debug("{}Passive Authentication: Signature check OK", logPrefix);
      Certificate verifier = cmsSignatureChecker.getVerifierCertificate();
      return checkForDocumentType((X509Certificate)verifier) ? verifier : null;
    }
    catch (SignatureException | CMSException e)
    {
      log.debug("{}Passive Authentication: Check NEGATIVE", logPrefix, e);
      return null;
    }
  }

  /**
   * Check whether the given certificate contains only allowed document types.
   *
   * @param c certificate to check
   * @return <code>false</code> if a single non-allowed type is found, <code>true</code> otherwise
   */
  private boolean checkForDocumentType(X509Certificate c)
  {
    byte[] extValue = c.getExtensionValue("2.23.136.1.1.6.2");
    if (extValue == null)
    {
      return true;
    }
    try
    {
      ASN1 sequence = new ASN1(new ASN1(extValue).getValue());
      ASN1 set = sequence.getChildElements()[1];
      for ( ASN1 printableStr : set.getChildElements() )
      {
        String type = new String(printableStr.getValue());
        if (allowedDocumentTypes.contains(type))
        {
          continue;
        }
        if (type.length() != 2 || !allowedDocumentTypes.contains(type.substring(0, 1)))
        {
          return false;
        }
      }
    }
    catch (IOException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to check for allowed document types.", e);
      }
      return false;
    }
    return true;
  }

  private Set<String> getAllowedDocuments()
  {
    ConfigurationService configurationService = SpringApplicationContextHelper.getConfigurationService();
    Optional<String> optionalEidMeans = configurationService.getConfiguration()
                                                            .map(EidasMiddlewareConfig::getEidConfiguration)
                                                            .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans);
    HashSet<String> allowedDocuments = new HashSet<>(Set.of("A", "ID", "UB"));
    if (optionalEidMeans.isPresent() && !optionalEidMeans.get().isBlank())
    {
      Arrays.stream(optionalEidMeans.get().split(",")).map(String::trim).forEach(allowedDocuments::add);
    }
    // Default value if not configured or blank
    return allowedDocuments;
  }
}
