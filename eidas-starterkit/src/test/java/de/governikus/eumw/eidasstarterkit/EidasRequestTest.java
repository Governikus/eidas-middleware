/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


class EidasRequestTest
{

  private List<X509Certificate> authors;

  @BeforeEach
  void setUp() throws Exception
  {
    EidasSaml.init();
    authors = new ArrayList<>();
    X509Certificate cert = Utils.readCert(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509-old.cer"));
    authors.add(cert);
  }

  @Test
  void parseRequestWithoutProviderName() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithoutProviderName.xml"));
    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);

    Assertions.assertNull(eidasRequest.getProviderName());
    Assertions.assertNull(eidasRequest.getRequesterId());
  }

  @Test
  void parseRequestProviderNameAndRequesterIdPresent() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithProviderNameAndRequesterId.xml"));


    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request), authors);

    Assertions.assertEquals("DefaultProvider", eidasRequest.getProviderName());
    Assertions.assertEquals("Requester Provider", eidasRequest.getRequesterId());
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

  @Test
  void parseSamlRequestWithoutNameIDPolicy() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithoutNameIDPolicy.xml"));
    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request), null);

    Assertions.assertNull(eidasRequest.getNameIdPolicy());
  }

  @Test
  void parseSamlRequestWithUnsupportedNameIDPolicyType() throws Exception
  {
    byte[] request = Files.readAllBytes(Paths.get("src/test/resources/EidasSamlRequestWithWrongNameIDPolicyType.xml"));
    ErrorCodeException errorCodeException = Assertions.assertThrows(ErrorCodeException.class,
                                                                    () -> EidasSaml.parseRequest(new ByteArrayInputStream(request),
                                                                                                 null));
    Assertions.assertEquals(ErrorCode.INVALID_NAME_ID_TYPE, errorCodeException.getCode());
    Assertions.assertEquals(0, errorCodeException.getDetails().length);
    Assertions.assertEquals("Name id type is not supported.", errorCodeException.getMessage());
  }

  @Test
  void createSignedRequest() throws Exception
  {
    // Prepare request
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(EidasRequestTest.class.getResourceAsStream("/eidassignertest.p12"),
                                                       KeyStoreSupporter.KeyStoreType.PKCS12,
                                                       "123456");
    EidasSigner signer = new EidasSigner(true, (PrivateKey)keyStore.getKey("eidassignertest", "123456".toCharArray()),
                                         (X509Certificate)keyStore.getCertificate("eidassignertest"));
    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    // Create request
    byte[] request = EidasSaml.createRequest("issuer",
                                             "destination",
                                             "providerName",
                                             "requesterId",
                                             signer,
                                             reqAtt,
                                             SPTypeEnumeration.PUBLIC,
                                             EidasNameIdType.UNSPECIFIED,
                                             EidasLoaEnum.LOA_HIGH);

    // Validate request signature
    EidasRequest eidasRequest = EidasSaml.parseRequest(new ByteArrayInputStream(request),
                                                       List.of((X509Certificate)keyStore.getCertificate("eidassignertest")));
    Assertions.assertEquals("issuer", eidasRequest.getIssuer());
  }

  @Test
  void createUnsignedRequest() throws Exception
  {
    // Prepare request
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(EidasRequestTest.class.getResourceAsStream("/eidassignertest.p12"),
                                                       KeyStoreSupporter.KeyStoreType.PKCS12,
                                                       "123456");
    HashMap<EidasPersonAttributes, Boolean> reqAtt = new HashMap<>();
    reqAtt.put(EidasNaturalPersonAttributes.FIRST_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.FAMILY_NAME, true);
    reqAtt.put(EidasNaturalPersonAttributes.PERSON_IDENTIFIER, true);
    reqAtt.put(EidasNaturalPersonAttributes.BIRTH_NAME, false);
    reqAtt.put(EidasNaturalPersonAttributes.PLACE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.DATE_OF_BIRTH, false);
    reqAtt.put(EidasNaturalPersonAttributes.CURRENT_ADDRESS, false);

    // Create request
    byte[] request = EidasSaml.createRequest("issuer",
                                             "destination",
                                             "providerName",
                                             "requesterId",
                                             null,
                                             reqAtt,
                                             SPTypeEnumeration.PUBLIC,
                                             EidasNameIdType.UNSPECIFIED,
                                             EidasLoaEnum.LOA_HIGH);

    // Validate that the request does not contain a signature
    Assertions.assertThrows(ErrorCodeException.class,
                            () -> EidasSaml.parseRequest(new ByteArrayInputStream(request),
                                                         List.of((X509Certificate)keyStore.getCertificate("eidassignertest"))));
    Assertions.assertFalse(new String(request, StandardCharsets.UTF_8).contains("Signature"));
  }
}
