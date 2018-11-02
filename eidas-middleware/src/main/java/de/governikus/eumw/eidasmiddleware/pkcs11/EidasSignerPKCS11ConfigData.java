package de.governikus.eumw.eidasmiddleware.pkcs11;


import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.PKCS11ProviderFactory;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.SoftHsmCredentialConfiguration;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

public class EidasSignerPKCS11ConfigData {

    private static final Logger log = Logger.getLogger(EidasSignerPKCS11ConfigData.class.getName());
    private String[] hsmExternalCfgLocations;
    private String hsmPin;
    private String hsmLib;
    private String hsmProviderName;
    private String hsmSlot;
    int hsmSlotListIndex;
    int hsmSlotListIndexMaxRange;
    private String keySourcePass, keySourceAlias, keySourceCertLocation, keySourceKeyLocation;
    private String keySourcePassEnc, keySourceAliasEnc, keySourceCertLocationEnc, keySourceKeyLocationEnc;
    private List<SoftHsmCredentialConfiguration> credentialConfigurationList;

    public EidasSignerPKCS11ConfigData(String pkcs11ConfigLocation, String pkcs11Pin) throws IOException {
        log.info("Attempting to load PKCS#11 configuration from: " + pkcs11ConfigLocation);
        Properties prop = new Properties();
        prop.load(new FileInputStream(new File(pkcs11ConfigLocation)));
        hsmExternalCfgLocations = getPropertyArray(prop.getProperty("hsmExternalCfgLocations"),",");
        //Choose pkcs11PIN set through env variable over one set in properties file.
        hsmPin = pkcs11Pin !=null ? pkcs11Pin : prop.getProperty("hsmPin");
        hsmLib = prop.getProperty("hsmLib");
        hsmProviderName = prop.getProperty("hsmProviderName");
        hsmSlot = prop.getProperty("hsmSlot");
        hsmSlotListIndex = getInt(prop.getProperty("hsmSlotListIndex"));
        hsmSlotListIndexMaxRange = getInt(prop.getProperty("hsmSlotListIndexMaxRange"));
        keySourcePass = prop.getProperty("keySourcePass");
        keySourceAlias = prop.getProperty("keySourceAlias");
        keySourceCertLocation = prop.getProperty("keySourceCertLocation");
        keySourceKeyLocation = prop.getProperty("keySourceKeyLocation");
        keySourcePassEnc = prop.getProperty("keySourcePassEnc");
        keySourceAliasEnc = prop.getProperty("keySourceAliasEnc");
        keySourceCertLocationEnc = prop.getProperty("keySourceCertLocationEnc");
        keySourceKeyLocationEnc = prop.getProperty("keySourceKeyLocationEnc");
        credentialConfigurationList = Arrays.asList(
                new SoftHsmCredentialConfiguration(keySourceAlias,keySourceKeyLocation,keySourceCertLocation),
                new SoftHsmCredentialConfiguration(keySourceAliasEnc, keySourceKeyLocationEnc, keySourceCertLocationEnc)
        );

        log.info("PKCS#11 configuration loaded");
    }

    private String[] getPropertyArray(String data, String split) {
        if (data==null){
            return null;
        }
        return data.split(split);
    }

    private int getInt(String intStr) {
        try {
            return Integer.valueOf(intStr);
        } catch (Exception ex) {
            return 0;
        }
    }

    public PKCS11Provider getPKCS11Provider() throws Exception {
        PKCS11ProviderConfiguration configuration;
        if (hsmExternalCfgLocations != null) {
            configuration = new PKCS11ProvidedCfgConfiguration(Arrays.asList(hsmExternalCfgLocations));
            log.info("Setting up PKCS11 configuration based on externally provided PKCS11 config files");
        } else {
            if (keySourceKeyLocation != null && hsmPin != null) {
                PKCS11SoftHsmProviderConfiguration softHsmConfig = new PKCS11SoftHsmProviderConfiguration();
                softHsmConfig.setCredentialConfigurationList(credentialConfigurationList);
                softHsmConfig.setPin(hsmPin);
                configuration = softHsmConfig;
                log.info("Setting up PKCS11 configuration based on SoftHSM");
            } else {
                configuration = new PKCS11ProviderConfiguration();
                log.info("Setting up generic PKCS11 configuration");
            }
            configuration.setLibrary(hsmLib);
            configuration.setName(hsmProviderName);
            configuration.setSlot(hsmSlot);
            configuration.setSlotListIndex(hsmSlotListIndex);
            configuration.setSlotListIndexMaxRange(hsmSlotListIndexMaxRange);
        }

        PKCS11ProviderFactory factory = new PKCS11ProviderFactory(configuration);
        PKCS11Provider pkcs11Provider = factory.createInstance();
        return pkcs11Provider;
    }

    public String getKeySourcePass() {
        return keySourcePass;
    }

    public String getKeySourceAlias() {
        return keySourceAlias;
    }

    public String getKeySourceCertLocation() {
        return keySourceCertLocation;
    }

    public String getKeySourcePassEnc() {
        return keySourcePassEnc;
    }

    public String getKeySourceAliasEnc() {
        return keySourceAliasEnc;
    }

    public String getKeySourceCertLocationEnc() {
        return keySourceCertLocationEnc;
    }
}
