/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;


/**
 * Wrapper for checking a CMS signature, trust must either be given with single a trust anchor or with a
 * master list containing several trust anchors.
 *
 * @author tautenhahn
 */
public class CmsSignatureChecker
{

  private static final Log LOG = LogFactory.getLog(CmsSignatureChecker.class);

  private final Set<X509Certificate> trustAnchors = new HashSet<>();

  /**
   * Create new instance with given trust anchor
   *
   * @param trustAnchor
   */
  CmsSignatureChecker(X509Certificate trustAnchor)
  {
    this.trustAnchors.add(trustAnchor);
  }

  /**
   * Create new instance with given master list
   *
   * @param trustAnchors
   */
  CmsSignatureChecker(MasterList masterList)
  {
    this.trustAnchors.addAll(masterList.getCertificates());
  }

  /**
   * Return true if parameter value is signed with key belonging to trusted anchor certificate.
   *
   * @param signedData
   */
  @SuppressWarnings("unchecked")
  boolean checkEnvelopedSignature(byte[] signedData, String entityID)
  {
    try
    {
      CMSSignedData s = new CMSSignedData(signedData);
      Store<X509CertificateHolder> certstore = s.getCertificates();
      SignerInformationStore signers = s.getSignerInfos();
      for ( SignerInformation signer : signers.getSigners() )
      {
        X509CertificateHolder holder = (X509CertificateHolder)certstore.getMatches(signer.getSID())
                                                                       .iterator()
                                                                       .next();
        X509Certificate cert = (X509Certificate)Utils.readCert(new ByteArrayInputStream(holder.getEncoded()),
                                                               "X509");
        if (matches(cert))
        {
          return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                                                       .build(cert.getPublicKey()));
        }
        LOG.warn(entityID + ": got untrusted signature certificate:\n"
                 + Base64.getMimeEncoder().encodeToString(cert.getEncoded()));
      }
    }
    catch (RuntimeException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      LOG.error(entityID + ": cannot check signature", e);
      LOG.info(entityID + ": the data to be checked was:\n"
               + Base64.getMimeEncoder().encodeToString(signedData));
    }
    return false;
  }

  /**
   * Find cert (or signer of cert) in trust anchor list.
   *
   * @param cert
   * @return <code>true</code> if found, <code>false</code> otherwise
   */
  private boolean matches(X509Certificate cert)
  {
    if (trustAnchors.contains(cert))
    {
      return true;
    }
    Optional<X509Certificate> signer = trustAnchors.stream()
                                                   .filter(s -> s.getSubjectX500Principal()
                                                                 .equals(cert.getIssuerX500Principal()))
                                                   .findAny();
    if (!signer.isPresent())
    {
      return false;
    }

    try
    {
      cert.verify(signer.get().getPublicKey());
      return true;
    }
    catch (GeneralSecurityException e)
    {
      return false;
    }
  }
}
