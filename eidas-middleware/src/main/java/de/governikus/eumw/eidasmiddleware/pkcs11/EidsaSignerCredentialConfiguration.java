package de.governikus.eumw.eidasmiddleware.pkcs11;

import org.apache.xml.security.algorithms.JCEMapper;
import org.opensaml.security.x509.BasicX509Credential;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.credential.PKCS11NoTestCredential;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class EidsaSignerCredentialConfiguration {

    public static final String PKCS11_CONFIG_LOCATION = "PKCS11_CONFIG_LOCATION";
    public static final String PKCS11_PIN = "PKCS11_PIN";
    private static final Logger log = Logger.getLogger(EidsaSignerCredentialConfiguration.class.getName());
    private static BasicX509Credential samlMessageSigningCredential;
    private static String pkcs11ConfigLocation, pkcs11Pin;
    private static EidasSignerPKCS11ConfigData pkcs11Config;

    static {
        pkcs11ConfigLocation = System.getenv(PKCS11_CONFIG_LOCATION);
        pkcs11Pin = System.getenv(PKCS11_PIN);
        if (pkcs11ConfigLocation == null) {
            log.info("No PKCS#11 config location specified - loading default keys");
        } else {
            try {
                pkcs11Config = new EidasSignerPKCS11ConfigData(pkcs11ConfigLocation, pkcs11Pin);
                PKCS11Provider pkcs11Provider = pkcs11Config.getPKCS11Provider();
                samlMessageSigningCredential = new PKCS11NoTestCredential(
                        getCert(pkcs11Config.getKeySourceCertLocation()),
                        pkcs11Provider.getProviderNameList(),
                        pkcs11Config.getKeySourceAlias(),
                        pkcs11Config.getKeySourcePass()
                );
                log.info("Loaded SAML signing key from PKCS#11 provider source");
                JCEMapper.setProviderId(null);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static X509Certificate getCert(String keySourceCertLocation) throws IOException, CertificateException {
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(keySourceCertLocation);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            return cert;
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
    }

    private EidsaSignerCredentialConfiguration() {
    }

    public static BasicX509Credential getSamlMessageSigningCredential() {
        return samlMessageSigningCredential;
    }
}
