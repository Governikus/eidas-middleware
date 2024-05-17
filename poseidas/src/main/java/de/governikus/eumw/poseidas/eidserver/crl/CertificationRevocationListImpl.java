/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.eidserver.crl.exception.CertificateValidationException;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * A singleton implementation to download, validate and cache CRLs published in a certificate.
 */
@Slf4j
public class CertificationRevocationListImpl implements CertificationRevocationList
{

  private static CertificationRevocationListImpl crl = null;

  private final X509Certificate cscaRootCertificate;

  private final CrlFetcher crlFetcher;

  @Getter
  private static boolean isInitialized;

  @Getter
  private final CrlCache crlCache;

  /**
   * Constructor.
   *
   * @param masterList set of trusted certificates to validate the CRL signature
   * @param cscaRootCertificate to extract the CRL URL
   * @param crlFetcher Used to download the CRL
   * @param configurationService the service to load the eumw configuration from the database
   */
  private CertificationRevocationListImpl(Set<X509Certificate> masterList,
                                          X509Certificate cscaRootCertificate,
                                          CrlFetcher crlFetcher,
                                          ConfigurationService configurationService)
    throws CertificateException
  {
    Set<X509Certificate> trustSet;
    if (masterList == null)
    {
      trustSet = new HashSet<>();
    }
    else
    {
      trustSet = masterList;
    }

    if (cscaRootCertificate == null)
    {
      Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();
      if (configuration.isEmpty())
      {
        throw new IllegalStateException("Exception during initial retrieval of CRL. No eidas middleware configuration present");
      }
      String masterListTrustAnchorCertificateName = configuration.get()
                                                                 .getEidConfiguration()
                                                                 .getDvcaConfiguration()
                                                                 .stream()
                                                                 .findFirst()
                                                                 .orElseThrow(() -> new IllegalStateException("Exception during initial retrieval of CRL. No dvca configuration present"))
                                                                 .getMasterListTrustAnchorCertificateName();
      this.cscaRootCertificate = configurationService.getCertificate(masterListTrustAnchorCertificateName);
    }
    else
    {
      this.cscaRootCertificate = cscaRootCertificate;
    }

    if (crlFetcher == null)
    {
      this.crlFetcher = new HttpCrlFetcher(trustSet);
    }
    else
    {
      this.crlFetcher = crlFetcher;
    }

    this.crlCache = new SimpleCrlCache();
  }

  /**
   * Try to initialize CRL if not already done.
   * 
   * @param configurationService configuration
   * @param facade terminal permission data
   */
  public static synchronized void tryInitialize(ConfigurationService configurationService, TerminalPermissionAO facade)
  {
    if (isInitialized)
    {
      log.trace("CRL already initialized.");
      return;
    }

    Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();
    if (configuration.isEmpty())
    {
      log.warn("No eidas middleware configuration present. Can not initialize CRL");
      return;
    }

    Optional<TerminalPermission> terminalPermission = configuration.map(EidasMiddlewareConfig::getEidConfiguration)
                                                                   .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                                   .stream()
                                                                   .flatMap(List::stream)
                                                                   .filter(ServiceProviderType::isEnabled)
                                                                   .map(sp -> facade.getTerminalPermission(sp.getCVCRefID()))
                                                                   .filter(tp -> tp != null
                                                                                 && !ArrayUtil.isNullOrEmpty(tp.getMasterList()))
                                                                   .findAny();
    if (terminalPermission.isEmpty())
    {
      log.warn("No terminal permission with master list found. Can not initialize CRL");
      return;
    }
    MasterList ml = new MasterList(terminalPermission.get().getMasterList());
    initialize(new HashSet<>(ml.getCertificates()), configurationService);
  }

  /**
   * This method must be called before {@link #getInstance()} is called. <br>
   * The CRLs for the CSCA root certificate, which is read from the MasterListTrustAnchor, will be fetched.
   *
   * @param masterList set of trusted certificates to validate the CRL signature
   * @param configurationService the service to load the eumw configuration from the database
   * @throws IllegalStateException when the class is already initialized or there was an exception during the download
   *           of verification of the CRLs
   */
  public static synchronized void initialize(Set<X509Certificate> masterList, ConfigurationService configurationService)
  {
    initialize(masterList, null, null, configurationService);
  }

  /**
   * This method must be called before the first {@link #getInstance()} method is called. <br>
   * This should only be called in test classes where different certificates and implementations of
   * the @{@link CrlFetcher} are needed. In productive code {@link #initialize(Set)} should be called.
   *
   * @param masterList trusted certificates to validate the CRL signature
   * @param certificate certificate to extract the CRL URL, <code>null</code> to use the default certificate (masterlist
   *          trust anchor)
   * @param crlFetcher The @{@link CrlFetcher} that should be used to load CRLs, or <code>null</code> when the
   *          default @{@link CrlFetcher} should be used
   * @param configurationService the service to load the eumw configuration from the database
   * @throws IllegalStateException when the class is already initialized or there was an exception during the download
   *           of verification of the CRLs
   */
  static synchronized void initialize(Set<X509Certificate> masterList,
                                      X509Certificate certificate,
                                      CrlFetcher crlFetcher,
                                      ConfigurationService configurationService)
  {
    if (isInitialized)
    {
      throw new IllegalStateException("This class is already initialized and it can only be initialized once.");
    }
    try
    {
      crl = new CertificationRevocationListImpl(masterList, certificate, crlFetcher, configurationService);
      crl.fetchCrlForRoot();
      isInitialized = true;
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CRL_TRAP_LAST_RENEWAL_STATUS, 0);
      log.info("CRL successful initialized");
    }
    catch (CertificateValidationException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CRL_TRAP_LAST_RENEWAL_STATUS, 1);
      throw new IllegalStateException("Exception during initial retrieval of CRL", e);
    }
    catch (CertificateException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CRL_TRAP_LAST_RENEWAL_STATUS, 1);
      throw new IllegalStateException("Exception during initial retrieval of CRL. Illegal trusted anchor certificate",
                                      e);
    }
  }

  /**
   * Fetch the CRLs for the CSCA root certificate that was set in the constructor
   *
   * @throws CertificateValidationException
   */
  private void fetchCrlForRoot() throws CertificateValidationException
  {
    List<String> urls = getCrlDistributionPoints(cscaRootCertificate);
    for ( String url : urls )
    {
      crlCache.set(url, crlFetcher.get(url));
    }
  }

  /**
   * Get the singleton object for this class
   *
   * @return The @{@link CertificationRevocationListImpl} singleton instance
   * @throws IllegalStateException when the instance was not initialized, see {@link #initialize(Set)}
   */
  public static synchronized CertificationRevocationListImpl getInstance()
  {
    if (crl == null)
    {
      throw new IllegalStateException("Class is not initialized");
    }
    return crl;
  }

  /**
   * Creates a list of URLs from the CRL distribution points of the certificate.
   *
   * @param certificate from which the urls are retrieved
   * @return List with urls where the CRLs are published
   */
  public static List<String> getCrlDistributionPoints(X509Certificate certificate)
  {
    List<String> urls = new ArrayList<>();
    try
    {
      if (certificate == null || certificate.getNonCriticalExtensionOIDs() == null
          || !certificate.getNonCriticalExtensionOIDs().contains(Extension.cRLDistributionPoints.getId()))
      {
        return urls;
      }
      CRLDistPoint distPoint = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(certificate.getExtensionValue(Extension.cRLDistributionPoints.getId())));
      for ( DistributionPoint dp : distPoint.getDistributionPoints() )
      {
        DistributionPointName distributionPoint = dp.getDistributionPoint();
        if (distributionPoint != null && distributionPoint.getType() == DistributionPointName.FULL_NAME)
        {
          for ( GeneralName genName : ((GeneralNames)distributionPoint.getName()).getNames() )
          {
            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier)
            {
              urls.add(DERIA5String.getInstance(genName.getName()).getString());
            }
          }
        }
      }
      return urls;
    }
    catch (IOException e)
    {
      log.error("Could not read CRL Distribution Points from certificate with distinguished name: {} ",
                certificate.getSubjectDN().toString(),
                e);
    }
    return urls;
  }

  /**
   * Holds succeeded and failed crl renewals.
   * 
   * @param succeeded
   * @param failed
   */
  public record RenewCrlsLists(List<String> succeeded, List<String> failed) {
  }

  /**
   * Renews all CRLs that are stored in the {@link CrlCache}.
   */
  public RenewCrlsLists renewCrls()
  {
    RenewCrlsLists renewCrlsLists = new RenewCrlsLists(new ArrayList<>(), new ArrayList<>());
    Set<String> availableUrls = crlCache.getAvailableUrls();
    for ( String url : availableUrls )
    {
      log.debug("Renewing CRL for URL: {}", url);
      boolean fetchAndSaveCrl = fetchAndSaveCrl(url);
      if (fetchAndSaveCrl)
      {
        renewCrlsLists.succeeded.add(url);
      }
      else
      {
        renewCrlsLists.failed.add(url);
      }
    }
    return renewCrlsLists;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public X509CRL getX509CRL(String url)
  {
    CrlDao crlDao = crlCache.get(url);

    // Check if the URL is known to the cache
    if (crlDao == null)
    {
      log.debug("CrlCache does not contain a CRL for this URL, requesting a new one. URL: {}", url);
      if (!fetchAndSaveCrl(url))
      {
        return null;
      }
    }

    // Check if the CRL is not older than the cache time
    crlDao = crlCache.get(url);
    if (crlDao.isCrlOlderThan24Hours())
    {
      log.debug("Current CRL is older than the valid cache time, requesting a new CRL for URL {}", url);
      if (!fetchAndSaveCrl(url))
      {
        return null;
      }
    }

    // Check that the CRL did not reach its own expiration date
    crlDao = crlCache.get(url);
    if (isTimeForNextUpdate(crlDao.getX509CRL()))
    {
      log.debug("Current CRL already reached its expiration date, requesting a new CRL for URL {}", url);
      if (!fetchAndSaveCrl(url))
      {
        return null;
      }
    }

    // All checks completed, return the CRL
    return crlDao.getX509CRL();
  }


  /**
   * This method tries to fetch, validate, and store the CRL in the cache
   *
   * @param url The URL where the CRL should be fetched from
   * @return true when the CRL could be fetched, validated and stored, false when an exception occurred
   */
  private boolean fetchAndSaveCrl(String url)
  {
    try
    {
      X509CRL x509CRL = crlFetcher.get(url);
      if (x509CRL != null)
      {
        crlCache.set(url, x509CRL);
        SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CRL_TRAP_LAST_RENEWAL_STATUS, 0);
        return true;
      }
    }
    catch (CertificateValidationException e)
    {
      log.error("Cannot request a valid CRL for this URL: {}", url, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CRL_TRAP_LAST_RENEWAL_STATUS, 1);
      return false;
    }
    return false;
  }

  private boolean isTimeForNextUpdate(X509CRL crl)
  {
    return crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis();
  }


  /**
   * Check if a certificate is on the CRL.
   *
   * @param x509CertificateToCheck The certificate to be checked if it is on a CRL
   * @return True if the certificate is revoked or the CRL(s) for the certificate cannot be downloaded or verified,
   *         otherwise false.
   */
  public boolean isOnCRL(X509Certificate x509CertificateToCheck)
  {
    CertificationRevocationListImpl crlInt = CertificationRevocationListImpl.getInstance();
    List<String> urls = CertificationRevocationListImpl.getCrlDistributionPoints(x509CertificateToCheck);
    X509CRL x509CRL;
    for ( String url : urls )
    {
      x509CRL = crlInt.getX509CRL(url);

      if (x509CRL == null || x509CRL.isRevoked(x509CertificateToCheck))
      {
        log.debug("Certificate {} has been revoked!", x509CertificateToCheck.getSubjectDN().getName());
        return true;
      }
    }
    return false;
  }

  /**
   * Only meant for test purposes to reset the singleton object after every test
   */
  public static void reset()
  {
    crl = null;
    isInitialized = false;
  }

  /**
   * Returns the last successful crl retrieval timestamp
   *
   * @return last successful crl retrieval timestamp
   */
  public static long latestRetrieval()
  {
    CrlCache crlCache = getInstance().getCrlCache();
    Set<String> availableUrls = crlCache.getAvailableUrls();
    long latestRetrieval = 0;
    Long buffer;
    for ( String url : availableUrls )
    {
      buffer = crlCache.get(url).getLastUpdate();
      if (buffer != null && latestRetrieval < buffer)
      {
        latestRetrieval = buffer;
      }
    }
    return latestRetrieval;
  }
}
