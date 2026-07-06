package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.transport.https.InsecureTrustManager;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Provides the TLS certificates to an URL
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class TLSCertificateRequester
{

  private final ServerTlsCertificateSelector serverTlsCertificateSelector;

  private final SSLContext sslContext = buildSSLContext();


  /**
   * Tries to retrieve a TLS server certificate for a specific URL
   *
   * @param url The URL to get the TLS server certificate from
   * @return an optional contain the selected certificate or an empty optional if no certificate could be foudn or
   *         selected
   */
  public Optional<X509Certificate> requestTlsServerCertificate(String url)
  {
    if (StringUtils.isBlank(url))
    {
      log.debug("Cannot get own TLS certificate from empty URL");
      return Optional.empty();
    }

    Certificate[] certs;
    try (HttpClient client = HttpClient.newBuilder().sslContext(sslContext).build();)
    {
      HttpResponse<Void> response = client.send(HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                                                HttpResponse.BodyHandlers.discarding());

      certs = response.sslSession().orElseThrow(() -> new IOException("No SSL session found")).getPeerCertificates();
    }
    catch (IOException | InterruptedException e)
    {
      log.warn("Unable to retrieve TLS certificate", e);
      return Optional.empty();
    }

    if (ArrayUtil.isNullOrEmpty(certs))
    {
      log.warn("Unable to retrieve TLS certificate: no certificate returned");
      return Optional.empty();
    }

    List<X509Certificate> x509Certificates = Arrays.stream(certs)
                                                   .filter(X509Certificate.class::isInstance)
                                                   .map(X509Certificate.class::cast)
                                                   .toList();

    return serverTlsCertificateSelector.selectServerTlsCertificate(x509Certificates);
  }

  /**
   * An SSL context that trusts every certificate chain.
   */
  private SSLContext buildSSLContext()
  {
    try
    {
      SSLContext buildSslContext = SSLContext.getInstance("TLS");
      buildSslContext.init(null, InsecureTrustManager.getNoOpX509TrustManagers(), new java.security.SecureRandom());
      return buildSslContext;
    }
    catch (KeyManagementException | NoSuchAlgorithmException e)
    {
      log.error("Could not initialize SSL context for TLS certificate requesting", e);
      throw new RuntimeException(e);
    }
  }
}

