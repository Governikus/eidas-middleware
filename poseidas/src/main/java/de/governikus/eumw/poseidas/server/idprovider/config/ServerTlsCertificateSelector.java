package de.governikus.eumw.poseidas.server.idprovider.config;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import jakarta.validation.constraints.NotNull;

import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardbase.CollectionUtil;

import lombok.extern.log4j.Log4j2;


/**
 * Selects the TLS server certificate in a certificate chain
 */
@Log4j2
@Component
public class ServerTlsCertificateSelector
{

  /**
   * Selects the TLS server certificate in a certificate chain
   *
   * @param certificateChain the certificate chain.
   * @return an optional containing the selected certificate. An empty optional is returned if no specific certificate
   *         could be selected. The reason for an empty optional will be logged.
   */
  public Optional<X509Certificate> selectServerTlsCertificate(List<X509Certificate> certificateChain)
  {
    if (CollectionUtil.isNullOrEmpty(certificateChain))
    {
      log.warn("Cannot select own TLS server certificate: Cannot select TLS server certificate from empty chain");
      return Optional.empty();
    }

    if (certificateChain.size() == 1)
    {
      log.trace("Selected the only certificate from list as TLS server certificate: {}", certificateChain::getFirst);
      return Optional.ofNullable(certificateChain.getFirst());
    }

    List<X509Certificate> nonCaCertificates = certificateChain.stream()
                                                              .filter(ServerTlsCertificateSelector::isNotCaCertificate)
                                                              .toList();

    return switch (nonCaCertificates.size())
    {
      case 0 -> {
        log.warn("Cannot select own TLS server certificate: No certificate without CA flag found in certificate chain.");
        yield Optional.empty();
      }
      case 1 -> {
        log.trace("Selected the only non CA certificate from list as TLS server certificate: {}",
                  nonCaCertificates::getFirst);
        yield Optional.ofNullable(nonCaCertificates.getFirst());
      }
      default -> {
        log.warn("Cannot select own TLS server certificate: Found more then one non CA certificate in chain. Cannot select TLS server certificate.");
        yield Optional.empty();
      }
    };
  }

  /**
   * Checks if a certificate is not a CA.
   *
   * @param certificate the certificate to check
   * @return true if the certificate is <b>not</b> a CA certificate, false otherwise.
   */
  private static boolean isNotCaCertificate(@NotNull X509Certificate certificate)
  {
    boolean isNotCaCertificate = certificate.getBasicConstraints() < 0;

    log.trace("The certificate was {}detected as a CA certificate:\n{}",
              () -> isNotCaCertificate ? "not " : "",
              () -> certificate);

    return isNotCaCertificate;
  }



}
