/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.checker;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class ConfigurationChecker
{

  ConfigurationChecker() throws CertificateException
  {
    checkPoseidas();
  }

  private void checkPoseidas() throws CertificateException
  {
    // Read file
    File poseidas = Paths.get("POSeIDAS.xml").toFile();
    if (!poseidas.exists())
    {
      log.error("No POSeIDAS.xml file found in this working directory");
      return;
    }

    // Read config
    PoseidasCoreConfiguration coreConfig = XmlHelper.unmarshal(poseidas, PoseidasCoreConfiguration.class);

    // Extract SSL Keys
    SslKeysType sslKeysType = coreConfig.getServiceProvider()
                                        .get(0)
                                        .getEPAConnectorConfiguration()
                                        .getPkiConnectorConfiguration()
                                        .getSslKeys()
                                        .get(0);

    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(sslKeysType.getClientCertificate()
                                                                                                                       .get(0)));
    RSAPublicKey rsaPublicKey = (RSAPublicKey)certificate.getPublicKey();
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)KeyReader.readPrivateKey(sslKeysType.getClientKey());

    if (rsaPublicKey.getModulus().equals(rsaPrivateKey.getModulus())
        && BigInteger.valueOf(2)
                     .modPow(rsaPublicKey.getPublicExponent()
                                         .multiply(rsaPrivateKey.getPrivateExponent())
                                         .subtract(BigInteger.ONE),
                             rsaPublicKey.getModulus())
                     .equals(BigInteger.ONE))
    {
      log.info("Private Key and Certificate match");
    }
    else
    {
      log.error("Private Key and Certificate DO NOT match");
    }
  }
}
