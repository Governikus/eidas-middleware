package de.governikus.eumw.poseidas.server.timer;

import static org.mockito.Mockito.lenient;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PendingCertificateRequest;
import de.governikus.eumw.poseidas.server.pki.PendingCertificateRequestRepository;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;


@ExtendWith(MockitoExtension.class)
class RequestSignerCvcRenewTimerTest
{

  @Mock
  private RequestSignerCertificateService rscService;

  @Mock
  private TerminalPermissionAO terminalPermissionAO;

  @Mock
  private ConfigurationService configurationService;

  @Mock
  private PendingCertificateRequestRepository pendingCertificateRequestRepository;

  @Mock
  private EidasMiddlewareConfig eidasMiddlewareConfig;

  @Mock
  private EidasMiddlewareConfig.EidConfiguration eidConfiguration;


  @Mock
  private ServiceProviderType serviceProviderType;

  @Mock
  private TerminalPermission terminalPermission;

  @Mock
  private PermissionDataHandling permissionDataHandling;

  @Mock
  private PendingCertificateRequest pendingCertificateRequest;

  @InjectMocks
  private RequestSignerCvcRenewTimer requestSignerCvcRenewTimer;


  @BeforeEach
  public void setup()
  {
    requestSignerCvcRenewTimer.timerRateInSeconds = 120;
    lenient().when(rscService.hasRequestSignerCertificate(Mockito.anyString())).thenReturn(true);

    lenient().when(configurationService.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));
    lenient().when(eidasMiddlewareConfig.getEidConfiguration()).thenReturn(eidConfiguration);
    lenient().when(eidConfiguration.getServiceProvider()).thenReturn(List.of(serviceProviderType));
    lenient().when(serviceProviderType.getName()).thenReturn("SpName");
    lenient().when(serviceProviderType.getCVCRefID()).thenReturn("CVCREFID1");

    lenient().when(terminalPermissionAO.getTerminalPermission(Mockito.anyString())).thenReturn(terminalPermission);
    lenient().when(pendingCertificateRequestRepository.findById(Mockito.anyString())).thenReturn(Optional.empty());
  }

  static List<Arguments> arguments()
  {
    // First: Seconds cvc is invalid
    // Second: should cvc be requested
    // Third: Time since last renew (pending request) or null if no renew should be mocked
    List<Object[]> testCases = new LinkedList<>();
    testCases.add(new Object[]{-100, false, null}); // valid
    testCases.add(new Object[]{1, true, null}); // One second invalid
    testCases.add(new Object[]{60 * 5, true, null}); // 5 min invalid

    testCases.add(new Object[]{60 * 60 * 6, true, null}); // 6 hours invalid
    testCases.add(new Object[]{60 * 60 * 12, true, null}); // 12 hours invalid
    testCases.add(new Object[]{60 * 60 * 18, true, null}); // 18 hours invalid
    testCases.add(new Object[]{60 * 60 * 24, true, null}); // 24 hours invalid
    testCases.add(new Object[]{60 * 60 * 30, true, null}); // 30 hours invalid
    testCases.add(new Object[]{60 * 60 * 36, true, null}); // 36 hours invalid
    testCases.add(new Object[]{60 * 60 * 42, true, null}); // 42 hours invalid
    testCases.add(new Object[]{60 * 60 * 47, true, null}); // 47 hours invalid
    testCases.add(new Object[]{60 * 60 * 49, false, null}); // 49 hours invalid

    testCases.add(new Object[]{60 * 60 * 24 * 3, false, null}); // 3 days invalid

    testCases.add(new Object[]{60 * 5, false, 60 * 2}); // 5 min invalid with pending
    testCases.add(new Object[]{60 * 60 * 7, true, 60 * 60 * 6}); // 7 hours invalid with pending before 6 hours
    testCases.add(new Object[]{60 * 60 * 24 * 3, false, 60 * 60 * 8}); // 3 days invalid pending before 8 hours

    return testCases.stream().map(e -> (Arguments)() -> e).collect(Collectors.toList());
  }

  @ParameterizedTest
  @MethodSource("arguments")
  void checkForInvalidCVCsWithRsCertificate(long invalidSeconds, boolean shouldRenew, Integer minutesSinceLastRequest)
  {

    // Setup
    lenient().when(terminalPermissionAO.getExpirationDates())
             .thenReturn(Map.of("CVCREFID1", Date.from(Instant.now().minusSeconds(invalidSeconds))));
    // Mock pending request if necessary
    if (minutesSinceLastRequest != null)
    {
      lenient().when(pendingCertificateRequestRepository.findById(Mockito.anyString()))
               .thenReturn(Optional.of(pendingCertificateRequest));
      lenient().when(pendingCertificateRequest.getLastChanged())
               .thenReturn(java.util.Date.from(Instant.now().minus(minutesSinceLastRequest, ChronoUnit.MINUTES)));
    }

    // Act
    requestSignerCvcRenewTimer.checkForInvalidCVCsWithRsCertificate();

    // Check
    Mockito.verify(permissionDataHandling, shouldRenew ? Mockito.atLeastOnce() : Mockito.never())
           .triggerCertRenewal(serviceProviderType.getName());
  }

  @Test
  void testExpiryCheck()
  {
    Instant now = Instant.now();
    Assertions.assertTrue(isCvcExpiredLessThanTwoDays(now.minus(2, ChronoUnit.SECONDS))); // 2 seconds invalid
    Assertions.assertTrue(isCvcExpiredLessThanTwoDays(now.minus(47, ChronoUnit.HOURS))); // 47 hours invalid
    Assertions.assertFalse(isCvcExpiredLessThanTwoDays(now.minus(2, ChronoUnit.DAYS))); // 2 days invalid
    Assertions.assertFalse(isCvcExpiredLessThanTwoDays(now.plus(2, ChronoUnit.SECONDS))); // 2 seconds valid
    Assertions.assertFalse(isCvcExpiredLessThanTwoDays(now.plus(2, ChronoUnit.DAYS))); // 2 days invalid
  }

  private static boolean isCvcExpiredLessThanTwoDays(Instant minus)
  {
    return RequestSignerCvcRenewTimer.isCvcExpiredLessThanTwoDays(Date.from(minus));
  }
}
