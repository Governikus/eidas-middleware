/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.security.Security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.utils.key.SecurityProvider;


@SpringBootApplication
@ComponentScan(basePackages = {"de.governikus.eumw"})
@ServletComponentScan(basePackages = {"de.governikus.eumw.poseidas.paosservlet.authentication.paos",
                                      "de.governikus.eumw.eidasmiddleware"})
@EnableTransactionManagement
@EnableScheduling
public class EIDASMiddlewareApplication
{

  public static void main(String[] args)
  {
    // add bouncy for brainpool and ECDH
    Security.insertProviderAt(SecurityProvider.BOUNCY_CASTLE_JSSE_PROVIDER, 1);
    Security.insertProviderAt(SecurityProvider.BOUNCY_CASTLE_PROVIDER, 2);
    Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    System.setProperty("jdk.tls.ephemeralDHKeySize", String.valueOf(Utils.MIN_EPHEMERAL_DH_KEY_SIZE));

    System.setProperty("jdk.tls.namedGroups",
                       "brainpoolP512r1,brainpoolP384r1,brainpoolP256r1,secp521r1,secp384r1,secp256r1,ffdhe4096,ffdhe3072,brainpoolP512r1tls13,brainpoolP384r1tls13,brainpoolP256r1tls13");

    //@formatter:off
    System.setProperty("jdk.tls.server.SignatureSchemes",
                       // Brainpool TLS 1.3
                       "ecdsa_brainpoolP512r1tls13_sha512,ecdsa_brainpoolP384r1tls13_sha384,ecdsa_brainpoolP256r1tls13_sha256,"
                       // ECDSA TLS 1.3 + TLS 1.2
                       +"ecdsa_secp521r1_sha512,ecdsa_secp384r1_sha384,ecdsa_secp256r1_sha256,"
                       // RSA PSS TLS 1.3 + TLS 1.2
                       +"rsa_pss_pss_sha512,rsa_pss_pss_sha384,rsa_pss_pss_sha256,"
                       // RSA TLS 1.3 + TLS 1.2
                       +"rsa_pss_rsae_sha512,rsa_pss_rsae_sha384,rsa_pss_rsae_sha256,"
                       // RSA TLS 1.2
                       +"rsa_pkcs1_sha512,rsa_pkcs1_sha384,rsa_pkcs1_sha256");
    //@formatter:on

    Security.setProperty("jdk.tls.disabledAlgorithms",
                         "SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, MD5withRSA, MD5, DSA, rsa_pkcs1_sha1, ecdsa_sha1, DH keySize < "
                                                       + Utils.MIN_EPHEMERAL_DH_KEY_SIZE + ", ECDH keySize < "
                                                       + Utils.MIN_KEY_SIZE_EC_TLS + ", EC keySize < "
                                                       + Utils.MIN_KEY_SIZE_EC_TLS + ", RSA keySize < "
                                                       + Utils.MIN_KEY_SIZE_RSA_TLS
                                                       + ", 3DES_EDE_CBC, anon, NULL, ECDH");
    Security.setProperty("crypto.policy", "unlimited");

    // Do not break SAML CipherValue content to prevent CR HTML entities in the content
    System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");

    SpringApplication.run(EIDASMiddlewareApplication.class, args);
  }
}
