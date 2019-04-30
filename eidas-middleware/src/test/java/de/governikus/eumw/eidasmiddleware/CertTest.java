/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.Before;
import org.junit.Test;


public class CertTest
{

  @Before
  public void setUp() throws Exception
  {}

  @Test
  public void test() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
    CertificateException, IOException, NoSuchProviderException
  {
    /*
     * String s = UUID.randomUUID().toString(); Utils.X509KeyPair keyPair =
     * Utils.ReadPKCS12(CertTest.class.getResourceAsStream("client_a.p12"),"123456".toCharArray());
     * Assert.assertTrue(true);
     */
  }
}
