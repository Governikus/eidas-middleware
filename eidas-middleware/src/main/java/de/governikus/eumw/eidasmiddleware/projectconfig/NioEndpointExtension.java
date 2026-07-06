package de.governikus.eumw.eidasmiddleware.projectconfig;

import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.openssl.ciphers.Cipher;
import org.apache.tomcat.util.net.openssl.ciphers.Group;
import org.apache.tomcat.util.net.openssl.ciphers.SignatureScheme;


/**
 * An extension of the NioEndpoint that allows overwriting the SSL engine creation
 */
class NioEndpointExtension extends NioEndpoint
{

  /**
   * Overwritten to forcefully set the named groups after the tomcat filters all uncommon (unknwon) named groups.
   */
  @Override
  protected SSLEngine createSSLEngine(String sniHostName,
                                      List<Cipher> clientRequestedCiphers,
                                      List<String> clientRequestedApplicationProtocols,
                                      List<String> clientRequestedProtocols,
                                      List<Group> clientSupportedGroups,
                                      List<SignatureScheme> clientSignatureSchemes)
  {
    SSLEngine sslEngine = super.createSSLEngine(sniHostName,
                                                clientRequestedCiphers,
                                                clientRequestedApplicationProtocols,
                                                clientRequestedProtocols,
                                                clientSupportedGroups,
                                                clientSignatureSchemes);
    SSLParameters sslParameters = sslEngine.getSSLParameters();
    JreCompat.getInstance()
             .setNamedGroupsMethod(sslParameters,
                                   new String[]{"brainpoolP512r1", "brainpoolP384r1", "brainpoolP256r1", "secp521r1",
                                                "secp384r1", "secp256r1", "ffdhe4096", "ffdhe3072",
                                                "brainpoolP512r1tls13", "brainpoolP384r1tls13",
                                                "brainpoolP256r1tls13"});
    sslEngine.setSSLParameters(sslParameters);
    return sslEngine;
  }
}
