/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.security.Security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import de.governikus.eumw.eidascommon.Utils;


@SpringBootApplication
@ServletComponentScan
@ComponentScan(basePackages = {"de.governikus.eumw"})
@EnableTransactionManagement
public class EIDASMiddlewareApplication
{

  /**
   * The context path of the eIDAS Middleware
   */
  public static final String CONTEXT_PATH = "/eidas-middleware";

  public static void main(String[] args)
  {
    System.setProperty("jdk.tls.namedGroups", "secp521r1,secp384r1,secp256r1,secp224r1");
    Security.setProperty("jdk.tls.disabledAlgorithms",
                         "SSLv3, RC4, MD5, SHA1, DSA, DH keySize < " + Utils.MIN_KEY_SIZE_RSA_TLS
                                                       + ", ECDH keySize < " + Utils.MIN_KEY_SIZE_EC_TLS
                                                       + ", EC keySize < " + Utils.MIN_KEY_SIZE_EC_TLS
                                                       + ", RSA keySize < " + Utils.MIN_KEY_SIZE_RSA_TLS);
    Security.setProperty("crypto.policy", "unlimited");

    SpringApplication.run(EIDASMiddlewareApplication.class, args);
  }

  /**
   * Set the context path programmatically
   */
  @Bean
  public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> webServerFactoryCustomizer()
  {
    return factory -> factory.setContextPath(CONTEXT_PATH);
  }
}
