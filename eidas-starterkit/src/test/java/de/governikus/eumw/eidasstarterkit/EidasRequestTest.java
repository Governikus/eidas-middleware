/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;


class EidasRequestTest
{

  private List<X509Certificate> authors;

  @BeforeEach
  public void setUp() throws Exception
  {
    EidasSaml.init();
    Security.addProvider(new BouncyCastleProvider());
    authors = new ArrayList<>();
    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"));
    authors.add(cert);
  }

  @Test
  void createParseRequestWithoutProviderName() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithoutProviderName.xml"));
    ErrorCodeException errorCodeException = Assertions.assertThrows(ErrorCodeException.class,
                                                                    () -> EidasSaml.parseRequest(new ByteArrayInputStream(request),
                                                                                                 authors));

    Assertions.assertEquals(ErrorCode.ILLEGAL_REQUEST_SYNTAX, errorCodeException.getCode());
    Assertions.assertEquals(1, errorCodeException.getDetails().length);
    Assertions.assertEquals("It was not possible to parse the SAML request: No requesterId or providerName attribute are present.",
                            errorCodeException.getMessage());
  }

  @Test
  void throwsExceptionWhenProviderNameAndRequesterIdPresent() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithProviderNameAndRequesterId.xml"));


    ErrorCodeException errorCodeException = Assertions.assertThrows(ErrorCodeException.class,
                                                                    () -> EidasSaml.parseRequest(new ByteArrayInputStream(request),
                                                                                                 authors));

    Assertions.assertEquals(ErrorCode.ILLEGAL_REQUEST_SYNTAX, errorCodeException.getCode());
    Assertions.assertEquals(1, errorCodeException.getDetails().length);
    Assertions.assertEquals("It was not possible to parse the SAML request: Both requesterId and providerName attributes are present.",
                            errorCodeException.getMessage());
  }

  @Test
  void parseSamlRequestWithOnlyProviderName() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithOnlyProviderName.xml"));
    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);

    Assertions.assertEquals("TestProvider", eidasRequest.getProviderName());
    Assertions.assertNull(eidasRequest.getRequesterId());
  }

  @Test
  void parseSamlRequestWithOnlyRequesterId() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithOnlyRequesterId.xml"));
    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);

    Assertions.assertNull(eidasRequest.getProviderName());
    Assertions.assertEquals("TestProvider", eidasRequest.getRequesterId());
  }
}
