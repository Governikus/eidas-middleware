/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasNameIdType;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


public class Metadatatest
{

  private X509KeyPair keyPair = null;

  private X509KeyPair keyPair2 = null;

  @Before
  public void setUp() throws Exception
  {
    EidasSaml.init();
    keyPair = Utils.readPKCS12(Metadatatest.class.getResourceAsStream("bos-test-tctoken.saml-sign.p12"),
                               "123456".toCharArray());

    keyPair2 = Utils.readPKCS12(Metadatatest.class.getResourceAsStream("bos-test-tctoken.saml-encr.p12"),
                                "123456".toCharArray());
  }

  @Test
  public void test() throws Exception
  {
    EidasOrganisation org = new EidasOrganisation("Gov", "Gov", "http://localhost", "de");
    EidasContactPerson p = new EidasContactPerson("Gov", "hans", "meyer", "0150", "test@test.de");
    List<EidasNameIdType> supportedNameIdTypes = new ArrayList<>();
    supportedNameIdTypes.add(EidasNameIdType.TRANSIENT);
    supportedNameIdTypes.add(EidasNameIdType.UNSPECIFIED);
    EidasSigner signer = new EidasSigner(true, keyPair.getKey(), keyPair.getCert());
    byte[] res = EidasSaml.createMetaDataNode("_dsfsdfs5454sfdsdfsdfsfd",
                                              "https://eubuild.tf.bos-test.de:8443/EidasSAMLDemo",
                                              Instant.now(),
                                              keyPair.getCert(),
                                              keyPair2.getCert(),
                                              org,
                                              p,
                                              p,
                                              "https://eubuild.tf.bos-test.de/EidasSAMLDemo/NewReceiverServlet",
                                              SPTypeEnumeration.PUBLIC,
                                              supportedNameIdTypes,
                                              signer);
    String xml = new String(res, StandardCharsets.UTF_8);
    Assert.assertTrue(xml != null);
    try (InputStream is = new ByteArrayInputStream(res))
    {
      EidasSaml.parseMetaDataNode(is, keyPair.getCert());
    }
  }
}
