/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.handler;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.stream.Stream;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Element;
import org.xml.sax.SAXParseException;

import de.governikus.eumw.eidascommon.CryptoAlgUtil;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


/**
 * Test the handling of incoming SAML requests
 */
@Slf4j
@ExtendWith(MockitoExtension.class)
@ExtendWith(SpringExtension.class)
class RequestHandlerTest
{

  @MockBean
  private RequestSessionRepository requestSessionRepository;

  @MockBean
  private ConfigurationService mockConfigurationService;

  private static final String RELAY_STATE = "State#1542107483529";

  private static final String POST_REQUEST = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6ZWlkYXM9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvc2FtbC1leHRlbnNpb25zIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL05ld1JlY2VpdmVyU2VydmxldCIgRm9yY2VBdXRobj0idHJ1ZSIgSUQ9Il9lYjc2ZjEwNS0xOTBlLTQyZmItOTRhMS01MzNhNDhhY2E3YWYiIElzUGFzc2l2ZT0iZmFsc2UiIElzc3VlSW5zdGFudD0iMjAxOC0xMS0xM1QxMToxMToyMy41MjlaIiBQcm92aWRlck5hbWU9IkRlZmF1bHRQcm92aWRlciIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL01ldGFkYXRhPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQo8ZHM6U2lnbmVkSW5mbz4NCjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwNy8wNS94bWxkc2lnLW1vcmUjc2hhMjU2LXJzYS1NR0YxIi8+DQo8ZHM6UmVmZXJlbmNlIFVSST0iI19lYjc2ZjEwNS0xOTBlLTQyZmItOTRhMS01MzNhNDhhY2E3YWYiPg0KPGRzOlRyYW5zZm9ybXM+DQo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4NCjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCjwvZHM6VHJhbnNmb3Jtcz4NCjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCjxkczpEaWdlc3RWYWx1ZT5WWnl2QkNKOS9qQUlIZzcvNlNveGU5RjRPRkMxem1ONlpwS0RkT2ticEI0PTwvZHM6RGlnZXN0VmFsdWU+DQo8L2RzOlJlZmVyZW5jZT4NCjwvZHM6U2lnbmVkSW5mbz4NCjxkczpTaWduYXR1cmVWYWx1ZT4NCldha1QxUlA1MzBaTWViQXhNVkFyQzJRZXN4bFBQU2UyTFlxRU5WTm9IemNISUdxV2xMa0lVT2duQlBnNklnOG9TNHo5eGZnVmluT3EmIzEzOw0KNmdpeTJoQ2lZY0g2OGJ2ZVVsYjVMNjNlejJoYUNuSFFSZVVla3hYTGFENGFuc0REOWkyVjJLUHlmS2oyR1RvbFlBdlpRbTExVEtLcSYjMTM7DQp6MGZmL0JhdVNpM2pwN1NHL3RiZUNiN1ZuM0puS1VCckVJZ3Rrc0Q3OHdrUHp0TFlLMWp0SzcrMzduZm9pU29YSWhDOFpOTG9mQWxrJiMxMzsNCmZkclFHN0g5cU5Da0YzVWs5UXV5a3ZORFhra3hiZ00xbXU2aEJ0THJNaWE5TzlOejVBL0hHQmJTcC9QcnhRRXZsUFpjT3p3ZU83aVQmIzEzOw0KdWN6djhiZW1vRVkvRGp5NWxpeWxSNkw4U0dBN3BLWTlVbmxtM2c9PQ0KPC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVOakNDQXg2Z0F3SUJBZ0lJTmtyKzhkM01iUGt3RFFZSktvWklodmNOQVFFTEJRQXdWekVuTUNVR0ExVUVBd3dlWW05eklFTkJJR1ZKUkNCRGIyMXRkVzVwWTJGMGFXOXVJRU5sY25Sek1SOHdIUVlEVlFRS0RCWmljbVZ0Wlc0Z2IyNXNhVzVsSUhObGNuWnBZMlZ6TVFzd0NRWURWUVFHRXdKRVJUQWVGdzB4TXpBMk1URXhNVE16TkRGYUZ3MHhOakEyTVRBeE1UTXpOREZhTUcweEl6QWhCZ05WQkFNTUdtSnZjeTEwWlhOMExYUmpkRzlyWlc0dWMyRnRiQzF6YVdkdU1SZ3dGZ1lEVlFRTERBOTBaWE4wWTJWeWRHbG1hV05oZEdVeEh6QWRCZ05WQkFvTUZtSnlaVzFsYmlCdmJteHBibVVnYzJWeWRtbGpaWE14Q3pBSkJnTlZCQVlUQW1SbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdCtHN3prUklDT2x5em1GNFZKYUJpMVRyMmZPd21iYXJEbXpoZ0VnS01kMWhRNU13MXdkcEVKMlNQcUlZNGVpdExIcjFpUHVDM21ERW9EV2NEMGxhNXFUQm9uUy9QUlZMSFNKRlBsc09qNGZJWjlyWTFFV1RWRmdYK1RyWm5PYXAxUTU1VzIyMktHVmJWeGY4RFZJUVhzcWxmZVJzZXNHZ3p3cG9zL1ZwZDA4Njc0SUJrWDJ6djdDV0dpSWhJbVBlZWlwb016RjNRcnhOSm1hR2o4RzlxT3ByQTA5Zy9HU2lrV21QVVFvbFN6RHZzYkV6LzgyNzVHYU5LRjlHR29hZkRabzlyUDhvSXdDd2hoTlludVhrMkhzcHhuRjlsY2xyWEdmN25HTk5WMlYyb2tSYzBybVF1OHBIenVtSXJkSEVSeHZtNVczeElPSlhPRUJlU0JwT0lRSURBUUFCbzRIdk1JSHNNQXdHQTFVZEV3RUIvd1FDTUFBd1B3WURWUjBsQkRnd05nWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RCQVlLS3dZQkJBR0NOeFFDQWdZS0t3WUJCQUdDTndvREREQWZCZ05WSFNNRUdEQVdnQlFGSXFrOCtLUVIvU3RhNDNMdzg1Y3pWSmx4anpBT0JnTlZIUThCQWY4RUJBTUNCTEF3SFFZRFZSME9CQllFRktZd1pKeCsyT3BGY2VPUStzNHFtZVdBYWt1Uk1Fc0dDQ3NHQVFVRkJ3RUJCRDh3UFRBN0JnZ3JCZ0VGQlFjd0FZWXZhSFIwY0RvdkwyOWpjM0F1WW05ekxXSnlaVzFsYmk1a1pTOXdkV0pzYVdOM1pXSXZjM1JoZEhWekwyOWpjM0F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxINS9tL21hWFFnNmREZ1REYzkrMjc1S1dNNVdBc1pFdmMrYjVOcUYvQUF5RkJvNnI1Y2NnZFF6a09xV2JWc29Gd1ZCWmxoQXgxOTZsWXpvdEpoVCtPcWcyWU5SYVB4UFIwb0NTdVh4ZHZVMFBDYzJrOHV6dWtoTFVCZHQ2ejlOOFVFcThONFNla1JUNW1lQzNjZEJQWnNEZWRldHBzZG9DWGZYdnl1TFJJRHp2bW5sZkJ4YWtLaEhXeXU5K3hEMGI1ZEhWbTIwU0dNSVBLVkZWaTkzd3FNeWRVbHRzSFlmVldlN1VpNHE0cW1OTEFOK1lHSFdhM2k2N3ZoMkVaSVMzYnZ4OWxKZk9USTRydlR0UlhjNVM2UHBLVXhodlcxczNZREpUeitraFIva0RYeFlTMlg2RzVQSFZYcktmbWEzMTFwbHB0My84TVZZaGgrcEV1R0ZSMD08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOkV4dGVuc2lvbnM+DQogICAgICAgIDxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGVzPg0KCQkJPGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9QbGFjZU9mQmlydGgiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIiBpc1JlcXVpcmVkPSJmYWxzZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vQ3VycmVudEdpdmVuTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0N1cnJlbnRGYW1pbHlOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0idHJ1ZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vUGVyc29uSWRlbnRpZmllciIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0RhdGVPZkJpcnRoIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0iZmFsc2UiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0N1cnJlbnRBZGRyZXNzIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0iZmFsc2UiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0JpcnRoTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9ImZhbHNlIi8+DQogICAgICAgIDwvZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlcz4NCiAgICA8L3NhbWwycDpFeHRlbnNpb25zPjxzYW1sMnA6TmFtZUlEUG9saWN5IEFsbG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCIvPjxzYW1sMnA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249Im1pbmltdW0iPg0KICAgICAgICA8c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWYgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvTG9BL2hpZ2g8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPg0KICAgIDwvc2FtbDJwOlJlcXVlc3RlZEF1dGhuQ29udGV4dD48L3NhbWwycDpBdXRoblJlcXVlc3Q+";

  private static final String INVALID_BASE64 = "D94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6ZWlkYXM9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvc2FtbC1leHRlbnNpb25zIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL05ld1JlY2VpdmVyU2VydmxldCIgRm9yY2VBdXRobj0idHJ1ZSIgSUQ9Il9lYjc2ZjEwNS0xOTBlLTQyZmItOTRhMS01MzNhNDhhY2E3YWYiIElzUGFzc2l2ZT0iZmFsc2UiIElzc3VlSW5zdGFudD0iMjAxOC0xMS0xM1QxMToxMToyMy41MjlaIiBQcm92aWRlck5hbWU9IkRlZmF1bHRQcm92aWRlciIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL01ldGFkYXRhPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQo8ZHM6U2lnbmVkSW5mbz4NCjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwNy8wNS94bWxkc2lnLW1vcmUjc2hhMjU2LXJzYS1NR0YxIi8+DQo8ZHM6UmVmZXJlbmNlIFVSST0iI19lYjc2ZjEwNS0xOTBlLTQyZmItOTRhMS01MzNhNDhhY2E3YWYiPg0KPGRzOlRyYW5zZm9ybXM+DQo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4NCjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCjwvZHM6VHJhbnNmb3Jtcz4NCjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCjxkczpEaWdlc3RWYWx1ZT5WWnl2QkNKOS9qQUlIZzcvNlNveGU5RjRPRkMxem1ONlpwS0RkT2ticEI0PTwvZHM6RGlnZXN0VmFsdWU+DQo8L2RzOlJlZmVyZW5jZT4NCjwvZHM6U2lnbmVkSW5mbz4NCjxkczpTaWduYXR1cmVWYWx1ZT4NCldha1QxUlA1MzBaTWViQXhNVkFyQzJRZXN4bFBQU2UyTFlxRU5WTm9IemNISUdxV2xMa0lVT2duQlBnNklnOG9TNHo5eGZnVmluT3EmIzEzOw0KNmdpeTJoQ2lZY0g2OGJ2ZVVsYjVMNjNlejJoYUNuSFFSZVVla3hYTGFENGFuc0REOWkyVjJLUHlmS2oyR1RvbFlBdlpRbTExVEtLcSYjMTM7DQp6MGZmL0JhdVNpM2pwN1NHL3RiZUNiN1ZuM0puS1VCckVJZ3Rrc0Q3OHdrUHp0TFlLMWp0SzcrMzduZm9pU29YSWhDOFpOTG9mQWxrJiMxMzsNCmZkclFHN0g5cU5Da0YzVWs5UXV5a3ZORFhra3hiZ00xbXU2aEJ0THJNaWE5TzlOejVBL0hHQmJTcC9QcnhRRXZsUFpjT3p3ZU83aVQmIzEzOw0KdWN6djhiZW1vRVkvRGp5NWxpeWxSNkw4U0dBN3BLWTlVbmxtM2c9PQ0KPC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVOakNDQXg2Z0F3SUJBZ0lJTmtyKzhkM01iUGt3RFFZSktvWklodmNOQVFFTEJRQXdWekVuTUNVR0ExVUVBd3dlWW05eklFTkJJR1ZKUkNCRGIyMXRkVzVwWTJGMGFXOXVJRU5sY25Sek1SOHdIUVlEVlFRS0RCWmljbVZ0Wlc0Z2IyNXNhVzVsSUhObGNuWnBZMlZ6TVFzd0NRWURWUVFHRXdKRVJUQWVGdzB4TXpBMk1URXhNVE16TkRGYUZ3MHhOakEyTVRBeE1UTXpOREZhTUcweEl6QWhCZ05WQkFNTUdtSnZjeTEwWlhOMExYUmpkRzlyWlc0dWMyRnRiQzF6YVdkdU1SZ3dGZ1lEVlFRTERBOTBaWE4wWTJWeWRHbG1hV05oZEdVeEh6QWRCZ05WQkFvTUZtSnlaVzFsYmlCdmJteHBibVVnYzJWeWRtbGpaWE14Q3pBSkJnTlZCQVlUQW1SbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdCtHN3prUklDT2x5em1GNFZKYUJpMVRyMmZPd21iYXJEbXpoZ0VnS01kMWhRNU13MXdkcEVKMlNQcUlZNGVpdExIcjFpUHVDM21ERW9EV2NEMGxhNXFUQm9uUy9QUlZMSFNKRlBsc09qNGZJWjlyWTFFV1RWRmdYK1RyWm5PYXAxUTU1VzIyMktHVmJWeGY4RFZJUVhzcWxmZVJzZXNHZ3p3cG9zL1ZwZDA4Njc0SUJrWDJ6djdDV0dpSWhJbVBlZWlwb016RjNRcnhOSm1hR2o4RzlxT3ByQTA5Zy9HU2lrV21QVVFvbFN6RHZzYkV6LzgyNzVHYU5LRjlHR29hZkRabzlyUDhvSXdDd2hoTlludVhrMkhzcHhuRjlsY2xyWEdmN25HTk5WMlYyb2tSYzBybVF1OHBIenVtSXJkSEVSeHZtNVczeElPSlhPRUJlU0JwT0lRSURBUUFCbzRIdk1JSHNNQXdHQTFVZEV3RUIvd1FDTUFBd1B3WURWUjBsQkRnd05nWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RCQVlLS3dZQkJBR0NOeFFDQWdZS0t3WUJCQUdDTndvREREQWZCZ05WSFNNRUdEQVdnQlFGSXFrOCtLUVIvU3RhNDNMdzg1Y3pWSmx4anpBT0JnTlZIUThCQWY4RUJBTUNCTEF3SFFZRFZSME9CQllFRktZd1pKeCsyT3BGY2VPUStzNHFtZVdBYWt1Uk1Fc0dDQ3NHQVFVRkJ3RUJCRDh3UFRBN0JnZ3JCZ0VGQlFjd0FZWXZhSFIwY0RvdkwyOWpjM0F1WW05ekxXSnlaVzFsYmk1a1pTOXdkV0pzYVdOM1pXSXZjM1JoZEhWekwyOWpjM0F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxINS9tL21hWFFnNmREZ1REYzkrMjc1S1dNNVdBc1pFdmMrYjVOcUYvQUF5RkJvNnI1Y2NnZFF6a09xV2JWc29Gd1ZCWmxoQXgxOTZsWXpvdEpoVCtPcWcyWU5SYVB4UFIwb0NTdVh4ZHZVMFBDYzJrOHV6dWtoTFVCZHQ2ejlOOFVFcThONFNla1JUNW1lQzNjZEJQWnNEZWRldHBzZG9DWGZYdnl1TFJJRHp2bW5sZkJ4YWtLaEhXeXU5K3hEMGI1ZEhWbTIwU0dNSVBLVkZWaTkzd3FNeWRVbHRzSFlmVldlN1VpNHE0cW1OTEFOK1lHSFdhM2k2N3ZoMkVaSVMzYnZ4OWxKZk9USTRydlR0UlhjNVM2UHBLVXhodlcxczNZREpUeitraFIva0RYeFlTMlg2RzVQSFZYcktmbWEzMTFwbHB0My84TVZZaGgrcEV1R0ZSMD08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOkV4dGVuc2lvbnM+DQogICAgICAgIDxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGVzPg0KCQkJPGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9QbGFjZU9mQmlydGgiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIiBpc1JlcXVpcmVkPSJmYWxzZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vQ3VycmVudEdpdmVuTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0N1cnJlbnRGYW1pbHlOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0idHJ1ZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vUGVyc29uSWRlbnRpZmllciIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0RhdGVPZkJpcnRoIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0iZmFsc2UiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0N1cnJlbnRBZGRyZXNzIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0iZmFsc2UiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0JpcnRoTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9ImZhbHNlIi8+DQogICAgICAgIDwvZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlcz4NCiAgICA8L3NhbWwycDpFeHRlbnNpb25zPjxzYW1sMnA6TmFtZUlEUG9saWN5IEFsbG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCIvPjxzYW1sMnA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249Im1pbmltdW0iPg0KICAgICAgICA8c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWYgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvTG9BL2hpZ2g8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPg0KICAgIDwvc2FtbDJwOlJlcXVlc3RlZEF1dGhuQ29udGV4dD48L3NhbWwycDpBdXRoblJlcXVlc3";

  private static final String INVALID_SIGNED_XML = "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";

  private static final String DEFAULT_PASSWORD = "123456";


  /**
   * Prepare mockServiceProvderConfig to return the necessary SAML signature cert
   */
  @BeforeEach
  public void setUp() throws URISyntaxException
  {
    RequestingServiceProvider sp = new RequestingServiceProvider("http://localhost:8080/eIDASDemoApplication/Metadata");

    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(signatureKeystore,
                                                                          "bos-test-tctoken.saml-sign")
                                                          .get());
    sp.setSectorType(SPTypeEnumeration.PUBLIC);
    Mockito.when(mockConfigurationService.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);
  }

  /**
   * Test various requests with null or empty string parameters
   */
  @Test
  void testMissingParametersForPost()
  {
    // both parameters null with POST
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(null,
                                                                                                                               null));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // saml request null with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLPostRequest(RELAY_STATE, null));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), ErrorCodeException.class);

    // both parameters emtpy String with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLPostRequest("", ""));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);

    // saml request emtpy String with POST
    requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                         () -> requestHandler.handleSAMLPostRequest(RELAY_STATE, ""));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(), SAXParseException.class);
  }

  /**
   * Test that a request with the wrong signature certificate is rejected
   */
  @Test
  void testPostWrongSignatureCertificate() throws URISyntaxException
  {
    // load the wrong certificate
    RequestingServiceProvider sp = new RequestingServiceProvider("http://localhost:8080/eIDASDemoApplication/Metadata");

    URL resource = RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-encr.p12");
    File keystoreFile = new File(resource.toURI());
    KeyStore signatureKeystore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(signatureKeystore,
                                                                          "bos-test-tctoken.saml-encr")
                                                          .get());
    Mockito.when(mockConfigurationService.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);

    // create the handler and process the rquest with the wrong signature
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               POST_REQUEST));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(),
                            ErrorCodeException.class,
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a changed digest value is rejected
   */
  @Test
  void testPostManipulatedXML()
  {
    // In this request some xml values were changed after the signature was added
    String wrongDigest = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6ZWlkYXM9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvc2FtbC1leHRlbnNpb25zIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL05ld1JlY2VpdmVyU2VydmxldCIgRm9yY2VBdXRobj0idHJ1ZSIgSUQ9Il80ZWMwNjFjNy1lZGQ4LTRiM2UtYWIyZi1jODNmNWU0YjZmZjIiIElzUGFzc2l2ZT0iZmFsc2UiIElzc3VlSW5zdGFudD0iMjAxOC0xMS0xM1QxNDowNTo0NS4wODFaIiBQcm92aWRlck5hbWU9IkRlZmF1bHRQcm92aWRlciIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL2xvY2FsaG9zdDo4MDgwL2VJREFTRGVtb0FwcGxpY2F0aW9uL01ldGFkYXRhPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQo8ZHM6U2lnbmVkSW5mbz4NCjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwNy8wNS94bWxkc2lnLW1vcmUjc2hhMjU2LXJzYS1NR0YxIi8+DQo8ZHM6UmVmZXJlbmNlIFVSST0iI180ZWMwNjFjNy1lZGQ4LTRiM2UtYWIyZi1jODNmNWU0YjZmZjIiPg0KPGRzOlRyYW5zZm9ybXM+DQo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4NCjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCjwvZHM6VHJhbnNmb3Jtcz4NCjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCjxkczpEaWdlc3RWYWx1ZT45K3FpWUh5N2xxVkpCOG9UYlUveldSVTRFblI1cU9xelZaQ3czZUdSNGVNPTwvZHM6RGlnZXN0VmFsdWU+DQo8L2RzOlJlZmVyZW5jZT4NCjwvZHM6U2lnbmVkSW5mbz4NCjxkczpTaWduYXR1cmVWYWx1ZT4NCkpnaFlFbGFINmMwb1YrNlVtR2RaTC9VK1ZvMXArL2hsN2NSQ2lSaDd0Q0ppT2RhSE1nbVl6Z2FJTUxpVFJrZUU1TXB3S2taeEFUUFImIzEzOw0KdWI0cHBPTHZJcVpFaXFKTW1lUWY1Tk5VSDhrVVQxQ1VibWFXTEhkM1VZSHQvWUlJV1YraFpSck5BNGNDQUQ2TzRPdk9mWHVweUU5WCYjMTM7DQpCaXJkV3Z3MkVjQWN1OWkzY0xsTFlXZ3BiRW9nS2QrNzR0NGU3M2xlVWY4Z0RxMXFYa3RaZFhqS0NwU1NSRGdkUC9vTTJ3MmxNZWNJJiMxMzsNCjlzVEhxMEhkUmxDcUJqNmRoc1ZTM3dhRGVvQXF3Sk91U0Ria2NmVjlDSFMzamxpekpwZkpud1YzdUVwSGJHN2NTRGRSSlAvMzBOOFUmIzEzOw0Kc1ZJazRjWjRGT29nTnQ4V0dvS2pXc25Oa3V5SmRCcHZIa3krcXc9PQ0KPC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVOakNDQXg2Z0F3SUJBZ0lJTmtyKzhkM01iUGt3RFFZSktvWklodmNOQVFFTEJRQXdWekVuTUNVR0ExVUVBd3dlWW05eklFTkJJR1ZKUkNCRGIyMXRkVzVwWTJGMGFXOXVJRU5sY25Sek1SOHdIUVlEVlFRS0RCWmljbVZ0Wlc0Z2IyNXNhVzVsSUhObGNuWnBZMlZ6TVFzd0NRWURWUVFHRXdKRVJUQWVGdzB4TXpBMk1URXhNVE16TkRGYUZ3MHhOakEyTVRBeE1UTXpOREZhTUcweEl6QWhCZ05WQkFNTUdtSnZjeTEwWlhOMExYUmpkRzlyWlc0dWMyRnRiQzF6YVdkdU1SZ3dGZ1lEVlFRTERBOTBaWE4wWTJWeWRHbG1hV05oZEdVeEh6QWRCZ05WQkFvTUZtSnlaVzFsYmlCdmJteHBibVVnYzJWeWRtbGpaWE14Q3pBSkJnTlZCQVlUQW1SbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdCtHN3prUklDT2x5em1GNFZKYUJpMVRyMmZPd21iYXJEbXpoZ0VnS01kMWhRNU13MXdkcEVKMlNQcUlZNGVpdExIcjFpUHVDM21ERW9EV2NEMGxhNXFUQm9uUy9QUlZMSFNKRlBsc09qNGZJWjlyWTFFV1RWRmdYK1RyWm5PYXAxUTU1VzIyMktHVmJWeGY4RFZJUVhzcWxmZVJzZXNHZ3p3cG9zL1ZwZDA4Njc0SUJrWDJ6djdDV0dpSWhJbVBlZWlwb016RjNRcnhOSm1hR2o4RzlxT3ByQTA5Zy9HU2lrV21QVVFvbFN6RHZzYkV6LzgyNzVHYU5LRjlHR29hZkRabzlyUDhvSXdDd2hoTlludVhrMkhzcHhuRjlsY2xyWEdmN25HTk5WMlYyb2tSYzBybVF1OHBIenVtSXJkSEVSeHZtNVczeElPSlhPRUJlU0JwT0lRSURBUUFCbzRIdk1JSHNNQXdHQTFVZEV3RUIvd1FDTUFBd1B3WURWUjBsQkRnd05nWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RCQVlLS3dZQkJBR0NOeFFDQWdZS0t3WUJCQUdDTndvREREQWZCZ05WSFNNRUdEQVdnQlFGSXFrOCtLUVIvU3RhNDNMdzg1Y3pWSmx4anpBT0JnTlZIUThCQWY4RUJBTUNCTEF3SFFZRFZSME9CQllFRktZd1pKeCsyT3BGY2VPUStzNHFtZVdBYWt1Uk1Fc0dDQ3NHQVFVRkJ3RUJCRDh3UFRBN0JnZ3JCZ0VGQlFjd0FZWXZhSFIwY0RvdkwyOWpjM0F1WW05ekxXSnlaVzFsYmk1a1pTOXdkV0pzYVdOM1pXSXZjM1JoZEhWekwyOWpjM0F3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxINS9tL21hWFFnNmREZ1REYzkrMjc1S1dNNVdBc1pFdmMrYjVOcUYvQUF5RkJvNnI1Y2NnZFF6a09xV2JWc29Gd1ZCWmxoQXgxOTZsWXpvdEpoVCtPcWcyWU5SYVB4UFIwb0NTdVh4ZHZVMFBDYzJrOHV6dWtoTFVCZHQ2ejlOOFVFcThONFNla1JUNW1lQzNjZEJQWnNEZWRldHBzZG9DWGZYdnl1TFJJRHp2bW5sZkJ4YWtLaEhXeXU5K3hEMGI1ZEhWbTIwU0dNSVBLVkZWaTkzd3FNeWRVbHRzSFlmVldlN1VpNHE0cW1OTEFOK1lHSFdhM2k2N3ZoMkVaSVMzYnZ4OWxKZk9USTRydlR0UlhjNVM2UHBLVXhodlcxczNZREpUeitraFIva0RYeFlTMlg2RzVQSFZYcktmbWEzMTFwbHB0My84TVZZaGgrcEV1R0ZSMD08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOkV4dGVuc2lvbnM+DQogICAgICAgIDxlaWRhczpTUFR5cGU+cHVibGljPC9laWRhczpTUFR5cGU+DQogICAgICAgIDxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGVzPg0KCQkJPGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9QbGFjZU9mQmlydGgiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIiBpc1JlcXVpcmVkPSJ0cnVlIi8+PGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9CaXJ0aE5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIiBpc1JlcXVpcmVkPSJ0cnVlIi8+PGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9DdXJyZW50QWRkcmVzcyIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz48ZWlkYXM6UmVxdWVzdGVkQXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uL0N1cnJlbnRGYW1pbHlOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0idHJ1ZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vRGF0ZU9mQmlydGgiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIiBpc1JlcXVpcmVkPSJ0cnVlIi8+PGVpZGFzOlJlcXVlc3RlZEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vZWlkYXMuZXVyb3BhLmV1L2F0dHJpYnV0ZXMvbmF0dXJhbHBlcnNvbi9DdXJyZW50R2l2ZW5OYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSIgaXNSZXF1aXJlZD0idHJ1ZSIvPjxlaWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9hdHRyaWJ1dGVzL25hdHVyYWxwZXJzb24vUGVyc29uSWRlbnRpZmllciIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiIGlzUmVxdWlyZWQ9InRydWUiLz4NCiAgICAgICAgPC9laWRhczpSZXF1ZXN0ZWRBdHRyaWJ1dGVzPg0KICAgIDwvc2FtbDJwOkV4dGVuc2lvbnM+PHNhbWwycDpOYW1lSURQb2xpY3kgQWxsb3dDcmVhdGU9InRydWUiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50Ii8+PHNhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0ibWluaW11bSI+DQogICAgICAgIDxzYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL2VpZGFzLmV1cm9wYS5ldS9Mb0EvaGlnaDwvc2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWY+DQogICAgPC9zYW1sMnA6UmVxdWVzdGVkQXV0aG5Db250ZXh0Pjwvc2FtbDJwOkF1dGhuUmVxdWVzdD4=";
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               wrongDigest));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a correct request via GET is accepted
   */
  @Test
  void testPostGeneratedRequest() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String request = createSAMLPostRequest(keyStore,
                                           DEFAULT_PASSWORD,
                                           "bos-test-tctoken.saml-sign",
                                           "http://localhost:8080/eIDASDemoApplication/Metadata",
                                           "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                           EidasLoaEnum.LOA_HIGH);
    EidasRequest eidasRequest = requestHandler.handleSAMLPostRequest(RELAY_STATE, request);
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a correct request without RelayState via GET is accepted
   */
  @Test
  void testPostGeneratedRequestWithoutRelayState() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String request = createSAMLPostRequest(keyStore,
                                           DEFAULT_PASSWORD,
                                           "bos-test-tctoken.saml-sign",
                                           "http://localhost:8080/eIDASDemoApplication/Metadata",
                                           "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                           EidasLoaEnum.LOA_HIGH);
    EidasRequest eidasRequest = requestHandler.handleSAMLPostRequest(null, request);
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a request containing a wrong issuer is rejected
   */
  @Test
  void testPostWrongIssuer() throws URISyntaxException
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String wrongIssuer = "http://wronghost:8080/eIDASDemoApplication/Metadata";
    String request = createSAMLPostRequest(keyStore,
                                           DEFAULT_PASSWORD,
                                           "bos-test-tctoken.saml-sign",
                                           wrongIssuer,
                                           "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                           EidasLoaEnum.LOA_HIGH);

    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               request));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a malformed base64 SAML request is rejected
   */
  @Test
  void testPostInvalidBase64()
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               INVALID_BASE64));
    Assertions.assertEquals(RequestProcessingException.class,
                            requestProcessingException.getClass(),
                            "RequestProcessingException expected");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test a request with invalid XML is rejected
   */
  @Test
  void testPostInvalidXML()
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               INVALID_SIGNED_XML));
    Assertions.assertEquals(SAXParseException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * MethodSource for testSha1PostRequest()
   */
  static Stream<Arguments> testSha1PostRequest()
  {
    return Stream.of(Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA256,
                                  "/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12",
                                  "bos-test-tctoken.saml-sign"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/de/governikus/eumw/eidasmiddleware/ecc2.p12",
                                  "ec_nist_p256"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA1,
                                  "/de/governikus/eumw/eidasmiddleware/ecc2.p12",
                                  "ec_nist_p256"),
                     Arguments.of(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
                                  SignatureConstants.ALGO_ID_DIGEST_SHA256,
                                  "/de/governikus/eumw/eidasmiddleware/ecc2.p12",
                                  "ec_nist_p256"));
  }

  @SneakyThrows
  @ParameterizedTest
  @MethodSource
  void testSha1PostRequest(String signatureAlgorithm, String digestAlgorithm, String keyStorePath, String alias)
  {
    File keystoreFile = new File(RequestHandlerTest.class.getResource(keyStorePath).toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    byte[] sha1SamlRequest = RequestHelper.createSamlPostRequest("http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                 "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                 (X509Certificate)keyStore.getCertificate(alias),
                                                                 (PrivateKey)keyStore.getKey(alias,
                                                                                             DEFAULT_PASSWORD.toCharArray()),
                                                                 signatureAlgorithm,
                                                                 digestAlgorithm);

    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLPostRequest(RELAY_STATE,
                                                                                                                               Base64.getEncoder()
                                                                                                                                     .encodeToString(sha1SamlRequest)));
    ErrorCodeException errorCodeException = (ErrorCodeException)requestProcessingException.getCause();
    Assertions.assertEquals(1, errorCodeException.getDetails().length);
    Assertions.assertEquals(CryptoAlgUtil.INVALID_HASH_OR_SIGNATURE_ALGORITHM, errorCodeException.getDetails()[0]);
  }

  /**
   * Test that a request with the wrong signature certificate is rejected
   */
  @Test
  void testGetWrongSignatureCertificate() throws URISyntaxException
  {
    // load the wrong certificate, in this case the encryption certificate
    RequestingServiceProvider sp = new RequestingServiceProvider("http://localhost:8080/eIDASDemoApplication/Metadata");

    File encryptionKeystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-encr.p12")
                                                                   .toURI());
    KeyStore encryptionKeystore = KeyStoreSupporter.readKeyStore(encryptionKeystoreFile, DEFAULT_PASSWORD);
    sp.setSignatureCert((X509Certificate)KeyStoreSupporter.getCertificate(encryptionKeystore,
                                                                          "bos-test-tctoken.saml-encr")
                                                          .get());
    Mockito.when(mockConfigurationService.getProviderByEntityID("http://localhost:8080/eIDASDemoApplication/Metadata"))
           .thenReturn(sp);

    // sign the saml request with the signature certificate, but validate it with the encryption certificate
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File signatureKeystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                                  .toURI());
    KeyStore signatureKeyStore = KeyStoreSupporter.readKeyStore(signatureKeystoreFile, DEFAULT_PASSWORD);
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(signatureKeyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     RELAY_STATE);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRedirectRequest(request.getSamlRequest(),
                                                                                                                                   request.getRelayState(),
                                                                                                                                   request.getSigAlg(),
                                                                                                                                   request.getSignature()));
    Assertions.assertEquals(requestProcessingException.getCause().getClass(),
                            ErrorCodeException.class,
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  @Test
  void testMissingParametersForRedirect()
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);

    // all parameters null with GET
    Assertions.assertThrows(RequestProcessingException.class,
                            () -> requestHandler.handleSAMLRedirectRequest(null, null, null, null));


    // saml request null with GET
    Assertions.assertThrows(RequestProcessingException.class,
                            () -> requestHandler.handleSAMLRedirectRequest(RELAY_STATE, null, null, null));

    // both parameters emtpy String with GET
    Assertions.assertThrows(RequestProcessingException.class,
                            () -> requestHandler.handleSAMLRedirectRequest("", "", "", ""));

    // saml request emtpy String with GET
    Assertions.assertThrows(RequestProcessingException.class,
                            () -> requestHandler.handleSAMLRedirectRequest(RELAY_STATE, "", "", ""));
  }

  /**
   * Test that a changed signature value is rejected
   */
  @Test
  void testRedirectManipulatedSignature() throws URISyntaxException
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(keyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     RELAY_STATE);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRedirectRequest(request.getSamlRequest(),
                                                                                                                                   request.getRelayState(),
                                                                                                                                   request.getSigAlg(),
                                                                                                                                   request.getSignature()
                                                                                                                                          .substring(0,
                                                                                                                                                     request.getSignature()
                                                                                                                                                            .length()
                                                                                                                                                        - 1)));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a correct request via GET is accepted
   */
  @Test
  void testRedirectGeneratedRequest() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(keyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     RELAY_STATE);
    EidasRequest eidasRequest = requestHandler.handleSAMLRedirectRequest(request.getSamlRequest(),
                                                                         request.getRelayState(),
                                                                         request.getSigAlg(),
                                                                         request.getSignature());
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a correct request without RelayState via GET is accepted
   */
  @Test
  void testRedirectGeneratedRequestWithoutRelayState() throws Exception
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(keyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     null);
    EidasRequest eidasRequest = requestHandler.handleSAMLRedirectRequest(request.getSamlRequest(),
                                                                         request.getRelayState(),
                                                                         request.getSigAlg(),
                                                                         request.getSignature());
    Assertions.assertNotNull(eidasRequest);
  }

  /**
   * Test that a request containing a wrong issuer is rejected
   */
  @Test
  void testRedirectWrongIssuer() throws URISyntaxException
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    String wrongIssuer = "http://wronghost:8080/eIDASDemoApplication/Metadata";
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(keyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     wrongIssuer,
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     null);

    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRedirectRequest(request.getSamlRequest(),
                                                                                                                                   request.getRelayState(),
                                                                                                                                   request.getSigAlg(),
                                                                                                                                   request.getSignature()));
    Assertions.assertEquals(ErrorCodeException.class,
                            requestProcessingException.getCause().getClass(),
                            "ErrorCodeException expected as cause");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  /**
   * Test that a malformed base64 SAML request is rejected
   */
  @Test
  void testRedirectInvalidBase64() throws URISyntaxException
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    File keystoreFile = new File(RequestHandlerTest.class.getResource("/de/governikus/eumw/eidasmiddleware/bos-test-tctoken.saml-sign.p12")
                                                         .toURI());
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keystoreFile, DEFAULT_PASSWORD);
    SamlRedirectRequestParameter request = createSAMLRedirectRequest(keyStore,
                                                                     DEFAULT_PASSWORD,
                                                                     "bos-test-tctoken.saml-sign",
                                                                     "http://localhost:8080/eIDASDemoApplication/Metadata",
                                                                     "http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                     EidasLoaEnum.LOA_HIGH,
                                                                     RELAY_STATE);
    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRedirectRequest(request.getSamlRequest()
                                                                                                                                          .substring(1),
                                                                                                                                   request.getRelayState(),
                                                                                                                                   request.getSigAlg(),
                                                                                                                                   request.getSignature()));
    Assertions.assertEquals(RequestProcessingException.class,
                            requestProcessingException.getClass(),
                            "RequestProcessingException expected");
    Assertions.assertEquals(RequestHandler.CANNOT_PARSE_SAML_REQUEST, requestProcessingException.getMessage());
  }

  @SneakyThrows
  @ParameterizedTest
  @ValueSource(strings = {XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1})
  void testSha1RedirectRequest(String signatureAlgorithm)
  {
    RequestHandler requestHandler = new RequestHandler(requestSessionRepository, mockConfigurationService);
    AuthnRequest unsignedAuthnRequest = RequestHelper.createUnsignedAuthnRequest("http://localhost:8080/eIDASDemoApplication/NewReceiverServlet",
                                                                                 "http://localhost:8080/eIDASDemoApplication/Metadata");
    AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
    Element element = arm.marshall(unsignedAuthnRequest);
    byte[] authnRequestBytes = RequestHelper.marshallAuthnRequest(element);

    RequestProcessingException requestProcessingException = Assertions.assertThrows(RequestProcessingException.class,
                                                                                    () -> requestHandler.handleSAMLRedirectRequest(HttpRedirectUtils.deflate(authnRequestBytes),
                                                                                                                                   RELAY_STATE,
                                                                                                                                   signatureAlgorithm,
                                                                                                                                   null));
    ErrorCodeException errorCodeException = (ErrorCodeException)requestProcessingException.getCause();
    Assertions.assertEquals(1, errorCodeException.getDetails().length);
    Assertions.assertEquals(CryptoAlgUtil.INVALID_HASH_OR_SIGNATURE_ALGORITHM, errorCodeException.getDetails()[0]);
  }

  /**
   * Create a SAML request that is ready to be sent via Post
   *
   * @param signKeystore the keystore that should be used to sign the request
   * @param password the password for the keystore
   * @param alias the alias for the keystore
   * @param issuerUrl The issuerURL for this request
   * @param destinationUrl the destinationURL for this request
   * @return The saml reqest as base54 and deflated to be send via GET
   */
  private String createSAMLPostRequest(KeyStore signKeystore,
                                       String password,
                                       String alias,
                                       String issuerUrl,
                                       String destinationUrl,
                                       EidasLoaEnum loA)
  {
    byte[] samlRequest;

    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    try
    {
      EidasSaml.init();
      EidasSigner signer = new EidasSigner(true, (PrivateKey)signKeystore.getKey(alias, password.toCharArray()),
                                           (X509Certificate)signKeystore.getCertificate(alias));

      samlRequest = EidasSaml.createRequest(issuerUrl,
                                            destinationUrl,
                                            signer,
                                            reqAtt,
                                            null,
                                            EidasNameIdType.TRANSIENT,
                                            loA);
    }
    catch (CertificateEncodingException | InitializationException | MarshallingException | SignatureException
      | TransformerFactoryConfigurationError | TransformerException | IOException | UnrecoverableKeyException
      | NoSuchAlgorithmException | KeyStoreException e)
    {
      log.error("Can not create Request", e);
      return null;
    }

    return Base64.getEncoder().encodeToString(samlRequest);
  }

  /**
   * Create a SAML request that is ready to be sent via Get
   *
   * @param relayState
   * @param signKeystore the keystore that should be used to sign the request
   * @param password the password for the keystore
   * @param alias the alias for the keystore
   * @param issuerUrl The issuerURL for this request
   * @param destinationUrl the destinationURL for this request
   * @return The saml reqest as base54 and deflated to be send via GET
   */
  private SamlRedirectRequestParameter createSAMLRedirectRequest(KeyStore signKeystore,
                                                                 String password,
                                                                 String alias,
                                                                 String issuerUrl,
                                                                 String destinationUrl,
                                                                 EidasLoaEnum loA,
                                                                 String relayState)
  {

    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    try
    {
      EidasSaml.init();
      // create unsigned request
      byte[] samlRequest = EidasSaml.createRequest(issuerUrl,
                                                   destinationUrl,
                                                   null,
                                                   reqAtt,
                                                   null,
                                                   EidasNameIdType.TRANSIENT,
                                                   loA);
      // create query string with detached signature
      String queryString = HttpRedirectUtils.createQueryString("http://test",
                                                               samlRequest,
                                                               true,
                                                               relayState,
                                                               (PrivateKey)signKeystore.getKey(alias,
                                                                                               password.toCharArray()),
                                                               "SHA256");

      // parse query string to return data object with the query parameters
      MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(queryString)
                                                                      .build()
                                                                      .getQueryParams();

      return new SamlRedirectRequestParameter(getQueryParameter(queryParams, HttpRedirectUtils.REQUEST_PARAMNAME),
                                              getQueryParameter(queryParams, HttpRedirectUtils.RELAYSTATE_PARAMNAME),
                                              getQueryParameter(queryParams, HttpRedirectUtils.SIGALG_PARAMNAME),
                                              getQueryParameter(queryParams, HttpRedirectUtils.SIGVALUE_PARAMNAME));
    }
    catch (Exception e)
    {
      log.error("Can not create Request", e);
      return null;
    }

  }

  private static String getQueryParameter(MultiValueMap<String, String> queryParams, String requestParamname)
    throws UnsupportedEncodingException
  {

    return queryParams.getFirst(requestParamname) == null ? null
      : URLDecoder.decode(queryParams.getFirst(requestParamname), Utils.ENCODING);
  }

  @Data
  private static class SamlRedirectRequestParameter
  {

    private final String samlRequest;

    private final String relayState;

    private final String sigAlg;

    private final String signature;
  }
}
