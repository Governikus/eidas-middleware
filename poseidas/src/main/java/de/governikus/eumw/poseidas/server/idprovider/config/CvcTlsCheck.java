/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.utils.key.exceptions.UnsupportedECCertificateException;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;


/**
 * This class tests the CVC for specific conditions like an entangled TLS certificate or a matching server URL
 */
@Slf4j
@AllArgsConstructor
@Component
public class CvcTlsCheck
{

  private static final String MESSAGE_NO_TLS_CLIENT_CERTIFICATE = "No TLS client certificate found for service provider {}";

  private TerminalPermissionAO facade;

  private final ConfigurationService configurationService;

  private final HSMServiceHolder hsmServiceHolder;

  /**
   * Performs the following checks: - TLS server certificate valid? - CVC valid? - server URL matches the one in CVC? -
   * TLS server certificate referenced in CVC?
   *
   * @return object holding the results
   */
  public Optional<CvcTlsCheckResult> check() throws UnsupportedECCertificateException
  {
    return check(true);
  }

  /**
   * Performs the following checks: - TLS server certificate valid? - CVC valid? - server URL matches the one in CVC? -
   * TLS server certificate referenced in CVC?
   *
   * @param checkECCertificate boolean. If true this method checks if the TLS certificate is a supported EC certificate,
   *          if an EC certificate is configured. If false, the check will not be performed.
   * @return object holding the results
   */
  public Optional<CvcTlsCheckResult> check(boolean checkECCertificate) throws UnsupportedECCertificateException
  {
    Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();
    if (configuration.isEmpty())
    {
      log.warn("No eidas middleware configuration present. Cannot perform CVC TLS checks");
      return Optional.empty();
    }
    EidasMiddlewareConfig config = configuration.get();
    CvcTlsCheckResult resultHolder = new CvcTlsCheckResult();
    Optional<X509Certificate> certificate = getOwnTlsCertificate(config.getServerUrl());

    // Test TLS Certificates
    if (certificate.isPresent())
    {
      X509Certificate cert = certificate.get();
      resultHolder.setServerTlsValid(testTlsValidity(cert));
      resultHolder.setServerTlsExpirationDate(cert.getNotAfter());

      if ("RSA".equals(cert.getPublicKey().getAlgorithm())
          && ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() < 3000)
      {
        resultHolder.getTlsRSACertsWithLengthLowerThan3000().add("TLS server certificate");
        log.warn("The TLS RSA server certificate has a bit length is lower than 3000. RSA certificates with a length lower than 3000 bits are only supported until end of 2025. Please make sure to change the certificate.");
      }


      if (checkECCertificate && "EC".equals(cert.getPublicKey().getAlgorithm()))
      {
        PublicKey publicKey = cert.getPublicKey();
        boolean isSupportedEC = false;
        if (publicKey instanceof java.security.interfaces.ECPublicKey pk)
        {
          final ECParameterSpec params = pk.getParams();
          isSupportedEC = isSupportedEC(EC5Util.convertSpec(params));
        }
        else if (publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey pk)
        {
          isSupportedEC = isSupportedEC(pk.getParameters());
        }

        if (!isSupportedEC)
        {
          throw new UnsupportedECCertificateException("The used EC certificate for TLS is not supported. The eIDAS Middleware will be shutdown.");
        }
      }
    }
    else
    {
      log.warn("TLS certificate not found for URL {} ", config.getServerUrl());
    }

    // Check CVCs
    configuration.map(EidasMiddlewareConfig::getEidConfiguration)
                 .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                 .stream()
                 .flatMap(List::stream)
                 .forEach(sp -> resultHolder.getProviderCvcChecks()
                                            .put(sp.getName(), getCvcResultsForSp(sp, config, certificate)));
    configuration.map(EidasMiddlewareConfig::getEidConfiguration)
                 .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                 .stream()
                 .flatMap(List::stream)
                 .forEach(sp -> resultHolder.getTlsRSACertsWithLengthLowerThan3000()
                                            .addAll(getServiceProviderWithRSATlsCertificateLowerThan3000Bits(sp)));
    return Optional.of(resultHolder);
  }

  /**
   * Performs the following checks for one service provider: - CVC valid? - server URL matches the one in CVC? - TLS
   * server certificate referenced in CVC?
   *
   * @param entityId the entity id for the service provider
   * @return object holding the results
   */
  public CvcCheckResults checkCvcProvider(String entityId)
  {
    Optional<EidasMiddlewareConfig> configuration = configurationService.getConfiguration();
    if (configuration.isEmpty())
    {
      log.warn("No eidas middleware configuration present. Cannot perform CVC TLS checks for service provider: {}",
               entityId);
      return null;
    }
    Optional<ServiceProviderType> serviceProvider = configuration.get()
                                                                 .getEidConfiguration()
                                                                 .getServiceProvider()
                                                                 .stream()
                                                                 .filter(sp -> sp.getName().equals(entityId))
                                                                 .findFirst();
    CvcCheckResults cvcResults = new CvcCheckResults();
    if (serviceProvider.isPresent())
    {
      ServiceProviderType sp = serviceProvider.get();
      Optional<X509Certificate> certificate = getOwnTlsCertificate(configuration.get().getServerUrl());
      cvcResults = getCvcResultsForSp(sp, configuration.get(), certificate);
    }
    return cvcResults;
  }

  /**
   * Tests the CVC of a service provider
   *
   * @param sp service provider to test
   * @param config
   * @param certificate server TLS certificate
   * @return
   */
  public CvcCheckResults getCvcResultsForSp(ServiceProviderType sp,
                                            EidasMiddlewareConfig config,
                                            Optional<X509Certificate> certificate)
  {
    CvcCheckResults cvcResults = new CvcCheckResults();
    TerminalPermission tp = facade.getTerminalPermission(sp.getCVCRefID());
    if (tp != null)
    {
      try
      {
        TerminalData data = tp.getFullCvc();
        cvcResults.setCvcPresent(true);
        cvcResults.setCvcValidity(testCvcExpired(data));
        cvcResults.setCvcUrlMatch(testCvcUrlMatch(data, config.getServerUrl()));
        cvcResults.setCvcTlsMatch(testCvcTlsMatch(data, certificate));
      }
      catch (IllegalArgumentException e)
      {
        log.warn(e.getMessage());
      }
    }
    return cvcResults;
  }

  /**
   * Tests if a CVC is entangled with a given TLS certificated
   *
   * @param data Terminal data containing a CVC
   * @param certificate The TLS server certificate
   * @return
   */
  public static boolean testCvcTlsMatch(TerminalData data, Optional<X509Certificate> certificate)
  {
    if (certificate.isEmpty())
    {
      return false;
    }

    byte[] digest;
    try
    {
      MessageDigest md = DigestUtil.getDigestByOID(data.getPublicKey().getOID());
      digest = md.digest(certificate.get().getEncoded());
    }
    catch (IOException | NoSuchAlgorithmException | CertificateEncodingException e)
    {
      log.warn("Unable to check if TLS certificate is referenced in CVC {}: Exception {}",
               data.getHolderReferenceString(),
               e);
      return false;
    }

    if (data.getCVCDescription().getCommunicationCertificateHashes().stream().anyMatch(h -> ByteUtil.equals(h, digest)))
    {
      log.debug("TLS certificate is referenced in CVC {}", data.getHolderReferenceString());
      return true;
    }
    log.warn("TLS certificate is not referenced in CVC {}", data.getHolderReferenceString());
    return false;
  }

  /**
   * Tests if a given CVC is bound to the given server URL
   *
   * @param data Terminal data containing a CVC
   * @param serverUrl The server URL to check for
   * @return
   */
  protected static boolean testCvcUrlMatch(TerminalData data, String serverUrl)
  {
    URI serverUri = UriComponentsBuilder.fromUriString(serverUrl).build().toUri();
    URI subjectUri = UriComponentsBuilder.fromUriString(data.getCVCDescription().getSubjectUrl()).build().toUri();
    URI serverUrlToCompare = UriComponentsBuilder.fromUriString(serverUri.toString())
                                                 .port(getPort(serverUri))
                                                 .replacePath(null)
                                                 .replaceQuery(null)
                                                 .fragment(null)
                                                 .userInfo(null)
                                                 .build()
                                                 .toUri();
    URI subjectUrlToCompare = UriComponentsBuilder.fromUriString(subjectUri.toString())
                                                  .port(getPort(subjectUri))
                                                  .replacePath(null)
                                                  .replaceQuery(null)
                                                  .fragment(null)
                                                  .userInfo(null)
                                                  .build()
                                                  .toUri();

    boolean result = serverUrlToCompare.equals(subjectUrlToCompare);
    if (result)
    {
      log.debug("Server URL from config and CVC {} match", data.getHolderReferenceString());
    }
    else
    {
      log.warn("Server URL from config and CVC {} do not match", data.getHolderReferenceString());
    }
    return result;
  }

  private static int getPort(URI uri)
  {
    int port = uri.getPort();
    if (port == -1)
    {
      port = "https".equals(uri.getScheme()) ? 443 : 80;
    }
    return port;
  }

  /**
   * Tries to retrieve a TLS server certificate for a specific URL
   *
   * @param url The URL to get the TLS server certificate from
   * @return
   */
  public Optional<X509Certificate> getOwnTlsCertificate(String url)
  {
    if (StringUtils.isBlank(url))
    {
      return Optional.empty();
    }
    Certificate[] certs;
    try
    {
      URL currentUrl = new URL(url);
      URLConnection urlConn = currentUrl.openConnection();
      if (!(urlConn instanceof HttpsURLConnection))
      {
        log.warn("Unable to retrieve TLS certificate: no HTTPS connection");
        return Optional.empty();
      }
      HttpsURLConnection conn = (HttpsURLConnection)urlConn;
      conn.setSSLSocketFactory(getSSLSocketFactory());
      conn.connect();
      certs = conn.getServerCertificates();
    }
    catch (IOException | KeyManagementException | NoSuchAlgorithmException e)
    {
      log.warn("Unable to retrieve TLS certificate", e);
      return Optional.empty();
    }

    if (certs == null || certs.length == 0)
    {
      log.warn("Unable to retrieve TLS certificate: no certificate returned");
      return Optional.empty();
    }

    if (certs[0] instanceof X509Certificate)
    {
      return Optional.of((X509Certificate)certs[0]);
    }
    return Optional.empty();
  }

  /**
   * Trys to retrieve the expiration date of the servers TLS certifiacte
   *
   * @return The Date of expiration or an exception is thrown
   * @throws IOException
   */
  public Date getTLSExpirationDate() throws IOException
  {
    Optional<X509Certificate> ownTlsCertificate = getOwnTlsCertificate(configurationService.getConfiguration()
                                                                                           .orElseThrow(() -> new ConfigurationException("Cannot retrieve own TLS certificate. No eumw configuration present"))
                                                                                           .getServerUrl());
    return ownTlsCertificate.map(X509Certificate::getNotAfter)
                            .orElseThrow(() -> new IOException("Cannot retrieve own TLS certificate"));
  }

  // get an SSLSocketFactory trusting all certificates
  private static SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException
  {
    TrustManager[] trustAllCerts = {new X509TrustManager()
    {

      public X509Certificate[] getAcceptedIssuers()
      {
        return null;
      }

      public void checkClientTrusted(X509Certificate[] certs, String authType)
      {
        // nothing
      }

      public void checkServerTrusted(X509Certificate[] certs, String authType)
      {
        // nothing
      }
    }};

    SSLContext sc = SSLContext.getInstance("TLSv1.2");
    sc.init(null, trustAllCerts, new SecureRandom());
    return sc.getSocketFactory();
  }

  private static boolean testTlsValidity(X509Certificate certificate)
  {
    try
    {
      certificate.checkValidity();
      log.debug("TLS certificate valid");
      return true;
    }
    catch (CertificateExpiredException e)
    {
      log.warn("TLS certificate is expired: {}", certificate.getSubjectX500Principal().toString());
    }
    catch (CertificateNotYetValidException e)
    {
      log.warn("TLS certificate is not yet valid: {}", certificate.getSubjectX500Principal().toString());
    }
    return false;
  }

  private static boolean testCvcExpired(TerminalData data)
  {
    Date currentDate = new Date();
    boolean result = currentDate.before(data.getExpirationDate()) && currentDate.after(data.getEffectiveDate());
    if (result)
    {
      log.debug("CVC {} valid", data.getHolderReferenceString());
    }
    else
    {
      log.warn("CVC {} invalid", data.getHolderReferenceString());
    }
    return result;
  }

  private boolean isSupportedEC(org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec)
  {
    List<String> supportedECs = List.of("brainpoolP256r1",
                                        "brainpoolP384r1",
                                        "brainpoolP512r1",
                                        "P-256",
                                        "P-384",
                                        "P-521");

    for ( String supportedEC : supportedECs )
    {
      final X9ECParameters params = ECNamedCurveTable.getByName(supportedEC);
      if (params.getN().equals(ecParameterSpec.getN()) && params.getH().equals(ecParameterSpec.getH())
          && params.getCurve().equals(ecParameterSpec.getCurve()) && params.getG().equals(ecParameterSpec.getG()))
      {
        return true;
      }
    }
    return false;
  }

  private List<String> getServiceProviderWithRSATlsCertificateLowerThan3000Bits(ServiceProviderType sp)
  {
    List<String> spCertWithLengthLowerThan3000 = new ArrayList<>();

    X509Certificate certificate;

    // no HSM
    if (hsmServiceHolder.getKeyStore() == null)
    {
      String clientKeyPairName = sp.getClientKeyPairName();
      if (clientKeyPairName == null)
      {
        log.warn(MESSAGE_NO_TLS_CLIENT_CERTIFICATE, sp.getName());
        return spCertWithLengthLowerThan3000;
      }
      KeyPair clientKeyPair = configurationService.getKeyPair(clientKeyPairName);
      if (clientKeyPair == null)
      {
        log.warn(MESSAGE_NO_TLS_CLIENT_CERTIFICATE, sp.getName());
        return spCertWithLengthLowerThan3000;
      }
      certificate = clientKeyPair.getCertificate();
    }
    else
    // HSM
    {
      try
      {
        certificate = (X509Certificate)hsmServiceHolder.getKeyStore().getCertificate(sp.getCVCRefID());
      }
      catch (KeyStoreException e)
      {
        log.warn(MESSAGE_NO_TLS_CLIENT_CERTIFICATE, sp.getName());
        return spCertWithLengthLowerThan3000;
      }
    }

    if (certificate == null)
    {
      log.warn(MESSAGE_NO_TLS_CLIENT_CERTIFICATE, sp.getName());
      return spCertWithLengthLowerThan3000;
    }

    if ("RSA".equals(certificate.getPublicKey().getAlgorithm())
        && ((RSAPublicKey)certificate.getPublicKey()).getModulus().bitLength() < 3000)
    {
      spCertWithLengthLowerThan3000.add(sp.getName());
    }

    if (!spCertWithLengthLowerThan3000.isEmpty())
    {
      log.warn("The TLS RSA certificates for the following service provider have a bit length lower than 3000: "
               + spCertWithLengthLowerThan3000
               + ".\n RSA certificates with a length lower than 3000 bits are only supported until end of 2025. Please make sure to change the certificate.");
    }
    return spCertWithLengthLowerThan3000;
  }

  @Getter
  @NoArgsConstructor
  public static class CvcTlsCheckResult
  {

    @Setter
    boolean serverTlsValid;

    @Setter
    Date serverTlsExpirationDate;

    @Setter
    List<String> tlsRSACertsWithLengthLowerThan3000 = new ArrayList<>();

    Map<String, CvcCheckResults> providerCvcChecks = new HashMap<>();
  }

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class CvcCheckResults
  {

    boolean cvcPresent;

    boolean cvcValidity;

    boolean cvcUrlMatch;

    boolean cvcTlsMatch;

    @Override
    public String toString()
    {
      return "CvcCheckResults{" + "cvcPresent=" + cvcPresent + ", cvcValidity=" + cvcValidity + ", cvcUrlMatch="
             + cvcUrlMatch + ", cvcTlsMatch=" + cvcTlsMatch + '}';
    }
  }
}
