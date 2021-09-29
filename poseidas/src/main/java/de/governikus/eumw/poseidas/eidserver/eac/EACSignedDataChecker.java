/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.eac;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardserver.eac.crypto.SignedDataChecker;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.pki.CmsSignatureChecker;
import lombok.extern.slf4j.Slf4j;


/**
 * Modified code from the mCard. Checks a reply from the EID process and verifies if the certificate used to
 * sign the travel document is a trustworthy one from the master list.
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
   * @param allowedDocumentTypes
   */
  public EACSignedDataChecker(List<X509Certificate> masterList,
                              String logPrefix,
                              Set<String> allowedDocumentTypes)
  {
    super(logPrefix);
    cmsSignatureChecker = new CmsSignatureChecker(masterList);
    this.allowedDocumentTypes = new HashSet<>(allowedDocumentTypes);
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
      return false;
    }
    return true;
  }
}
