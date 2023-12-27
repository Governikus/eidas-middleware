package de.governikus.eumw.poseidas.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.config.model.CertificateInfoHolder;
import de.governikus.eumw.poseidas.config.model.CertificateUploadModel;
import de.governikus.eumw.poseidas.config.model.CreateCertificateFromKeystoreModel;
import de.governikus.eumw.poseidas.config.model.CreateKeypairFromKeystoreModel;
import de.governikus.eumw.poseidas.config.model.KeypairInfoHolder;
import de.governikus.eumw.poseidas.config.model.KeystoreInfoHolder;
import de.governikus.eumw.poseidas.config.model.KeystoreUploadModel;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.service.ConfigKeyDataService;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Handles all requests that are necessary for the key management
 */
@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.KEY_MANAGEMENT)
public class KeymanagementController
{


  private static final String COULD_NOT_READ_KEY_STORE = "Could not read key store";

  private static final String ALIAS = "alias";

  private static final String CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL = "createKeypairFromKeystoreModel";

  private static final String COULD_NOT_LOAD_KEY = "Could not load key";

  private static final String KEY_STORE_UPLOAD_MODEL = "keystoreUploadModel";

  private static final String CERTIFICATE_UPLOAD_MODEL = "certificateUploadModel";

  private static final String CERTIFICATES = "certificates";

  private static final String KEY_PAIRS = "keypairs";

  private static final String KEY_STORE_INFO_LIST = "keystoreInfoList";

  private static final String PAGES_KEY_MANAGEMENT_INDEX = "pages/keymanagement/index";

  private static final String ERROR = "error";

  private static final String KEY_STORE_INFO = "keyStoreInfo";

  private static final String CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL = "createCertificateFromKeystoreModel";

  private static final String PAGES_KEY_MANAGEMENT_CREATE_FROM_KEY_STORE = "pages/keymanagement/createFromKeystore";

  private static final String COULD_NOT_BE_FOUND = " could not be found";

  private static final String THIS_NAME_IS_ALREADY_TAKEN = "This name is already taken";

  private static final String KEY_STORE = "Key store ";

  private static final String REDIRECT_TO_INDEX = "redirect:" + ContextPaths.ADMIN_CONTEXT_PATH + "/keymanagement";

  private static final String JUMP_TO_TAB = "jumpToTab";

  private static final String KEY_STORES_TAB = "KeyStores";

  private static final String CERTIFICATES_TAB = "Certificates";

  private static final String KEY_PAIRS_TAB = "KeyPairs";

  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy", Locale.ENGLISH);

  private final ConfigurationService configurationService;

  private final ConfigKeyDataService configKeyDataService;

  /**
   * Index Page Show all information and options
   */
  @GetMapping
  public String index(Model model, @ModelAttribute String error, @ModelAttribute String msg)
  {
    if (StringUtils.isNotBlank(error))
    {
      model.addAttribute(ERROR, error);
    }
    if (StringUtils.isNotBlank(msg))
    {
      model.addAttribute("msg", msg);
    }

    model.addAttribute(KEY_STORE_UPLOAD_MODEL, new KeystoreUploadModel());
    model.addAttribute(CERTIFICATE_UPLOAD_MODEL, new CertificateUploadModel());
    model.addAttribute(CERTIFICATES, getCertificates());
    model.addAttribute(KEY_PAIRS, getKeyPairs());
    model.addAttribute(KEY_STORE_INFO_LIST, getKeyStores());
    return PAGES_KEY_MANAGEMENT_INDEX;
  }

  private List<CertificateInfoHolder> getCertificates()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getCertificate)
                               .stream()
                               .flatMap(List::stream)
                               .map(this::certificateTypeToInfoHolder)
                               .filter(Optional::isPresent)
                               .map(Optional::get)
                               .sorted(Comparator.comparing(CertificateInfoHolder::getName,
                                                            String.CASE_INSENSITIVE_ORDER))
                               .collect(Collectors.toList());

  }

  private List<KeypairInfoHolder> getKeyPairs()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getKeyPair)
                               .stream()
                               .flatMap(List::stream)
                               .map(this::keyPairTypeToInfoHolder)
                               .filter(Optional::isPresent)
                               .map(Optional::get)
                               .sorted(Comparator.comparing(KeypairInfoHolder::getName, String.CASE_INSENSITIVE_ORDER))
                               .collect(Collectors.toList());

  }

  private Optional<KeypairInfoHolder> keyPairTypeToInfoHolder(KeyPairType keyPairType)
  {

    final Optional<KeyStoreType> keyStoreTypeOptional = configurationService.getConfiguration()
                                                                            .stream()
                                                                            .map(EidasMiddlewareConfig::getKeyData)
                                                                            .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                                                                            .flatMap(List::stream)
                                                                            .filter(k -> keyPairType.getKeyStoreName()
                                                                                                    .equals(k.getName()))
                                                                            .findFirst();
    if (keyStoreTypeOptional.isEmpty())
    {
      if (log.isDebugEnabled())
      {
        log.debug("Could not find key store '{}' in configuration", keyPairType.getKeyStoreName());
      }
      return Optional.empty();
    }
    final KeyStoreType keyStoreType = keyStoreTypeOptional.get();

    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                          .value()),
                                                       keyStoreType.getPassword());


    try
    {
      X509Certificate cert = (X509Certificate)keyStore.getCertificate(keyPairType.getAlias());

      return Optional.of(new KeypairInfoHolder(keyPairType.getName(), cert.getSubjectX500Principal().getName(),
                                               cert.getIssuerX500Principal().getName(),
                                               "0x" + Hex.hexify(cert.getSerialNumber()),
                                               dateFormat.format(cert.getNotAfter()),
                                               cert.getNotAfter().after(Date.from(Instant.now())),
                                               keyStoreType.getName(), keyPairType.getAlias()));
    }
    catch (KeyStoreException e)
    {
      log.debug("Exception while working with certificate", e);
      return Optional.empty();
    }
  }


  private Optional<CertificateInfoHolder> certificateTypeToInfoHolder(CertificateType certificateType)
  {

    try
    {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      X509Certificate cert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificateType.getCertificate()));
      return Optional.of(new CertificateInfoHolder(certificateType.getName(), cert.getSubjectX500Principal().getName(),
                                                   cert.getIssuerX500Principal().getName(),
                                                   "0x" + Hex.hexify(cert.getSerialNumber()),
                                                   dateFormat.format(cert.getNotAfter()),
                                                   cert.getNotAfter().after(Date.from(Instant.now())),
                                                   certificateType.getKeystore(), certificateType.getAlias()));
    }
    catch (CertificateException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Exception while working with certificate " + certificateType.getName(), e);
      }
      return Optional.empty();
    }
  }


  /**
   * Creates a List of {@link KeystoreInfoHolder} from all currently saved key stores
   *
   * @return List of available {@link KeystoreInfoHolder}
   */
  private List<KeystoreInfoHolder> getKeyStores()
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                               .stream()
                               .flatMap(List::stream)
                               .map(this::keydataKeyStoreToInfoHolder)
                               .sorted(Comparator.comparing(KeystoreInfoHolder::getName, String.CASE_INSENSITIVE_ORDER))
                               .collect(Collectors.toList());
  }


  /**
   * Coverts a {@link KeystoreInfoHolder} to a {@link KeyStoreType} for the view
   *
   * @param keyStoreType Stored key store
   * @return given {@link KeyStoreType} as {@link KeystoreInfoHolder}
   */
  private KeystoreInfoHolder keydataKeyStoreToInfoHolder(KeyStoreType keyStoreType)
  {
    if (log.isDebugEnabled())
    {
      log.debug("Converting key store {} to a KeystoreInfoHolder", keyStoreType.getName());
    }
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                          .value()),
                                                       keyStoreType.getPassword());
    List<String> certificateAlias = new LinkedList<>();
    List<String> keypairAlias = new LinkedList<>();

    try
    {
      final Iterator<String> aliases = keyStore.aliases().asIterator();
      while (aliases.hasNext())
      {
        String alias = aliases.next();
        if (keyStore.isKeyEntry(alias))
        {
          keypairAlias.add(alias);
          certificateAlias.add(alias);
        }
        else if (keyStore.isCertificateEntry(alias))
        {
          certificateAlias.add(alias);
        }
      }
    }
    catch (KeyStoreException e)
    {
      if (log.isWarnEnabled())
      {
        log.warn("Could not read alias from stored key store " + keyStoreType.getName(), e);
      }
      // TODO: Handle exception
    }
    return new KeystoreInfoHolder(keyStoreType.getName(), keyStoreType.getType().value(), certificateAlias,
                                  keypairAlias);
  }

  /**
   * Allow to extract a key pair or a certificate from a saved key store.
   */
  @GetMapping("/createCertificateOrKeyFromKeystore")
  public String extractFromKeystore(Model model,
                                    @RequestParam("keystorename") String keyStoreName,
                                    @ModelAttribute String error,
                                    @ModelAttribute String msg,
                                    RedirectAttributes redirectAttributes)
  {
    if (StringUtils.isNotBlank(error))
    {
      model.addAttribute(ERROR, error);
    }
    if (StringUtils.isNotBlank(msg))
    {
      model.addAttribute("msg", msg);
    }

    final Optional<KeystoreInfoHolder> keyStoreInfoHolder = getKeystoreInfoHolder(keyStoreName);
    if (keyStoreInfoHolder.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, KEY_STORE + keyStoreName + COULD_NOT_BE_FOUND);
      return REDIRECT_TO_INDEX;
    }

    model.addAttribute(KEY_STORE_INFO, keyStoreInfoHolder.get());
    model.addAttribute(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, new CreateCertificateFromKeystoreModel());
    model.addAttribute(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, new CreateKeypairFromKeystoreModel());

    return PAGES_KEY_MANAGEMENT_CREATE_FROM_KEY_STORE;
  }

  /**
   * Upload a new key store.
   */
  @PostMapping("/uploadKeystore")
  public String uploadKeystore(Model model,
                               @ModelAttribute @Valid KeystoreUploadModel keyStoreUploadModel,
                               BindingResult bindingResult,
                               @RequestParam("keystoreFile") MultipartFile keyStoreFile,
                               RedirectAttributes redirectAttributes)
  {

    if (getKeyStores().parallelStream().anyMatch(k -> k.getName().equalsIgnoreCase(keyStoreUploadModel.getName())))
    {
      bindingResult.addError(new FieldError(KEY_STORE_UPLOAD_MODEL, "name", THIS_NAME_IS_ALREADY_TAKEN));
    }

    byte[] keyStoreFileBytes = null;

    if (Arrays.stream(KeyStoreTypeType.values()).anyMatch(d -> d.name().equals(keyStoreUploadModel.getKeyStoreType())))
    {
      try
      {
        keyStoreFileBytes = keyStoreFile.getBytes();
        KeyStoreSupporter.readKeyStore(keyStoreFileBytes,
                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreUploadModel.getKeyStoreType()
                                                                                                 .replace("_", "")),
                                       keyStoreUploadModel.getPassword());
      }
      catch (IOException e)
      {
        bindingResult.addError(new ObjectError(KEY_STORE_UPLOAD_MODEL, "Could not read uploaded file"));
      }
      catch (KeyStoreCreationFailedException e)
      {
        bindingResult.addError(new ObjectError(KEY_STORE_UPLOAD_MODEL,
                                               "Problem while loading the key store. " + e.getCause().getMessage()));
      }
    }
    else
    {
      bindingResult.addError(new FieldError(KEY_STORE_UPLOAD_MODEL, "keyStoreType", "This key store type is invalid"));
    }


    if (bindingResult.hasErrors())
    {
      model.addAttribute(CERTIFICATE_UPLOAD_MODEL, new CertificateUploadModel());
      model.addAttribute(KEY_STORE_INFO_LIST, getKeyStores());
      model.addAttribute(CERTIFICATES, getCertificates());
      model.addAttribute(KEY_PAIRS, getKeyPairs());
      model.addAttribute(JUMP_TO_TAB, KEY_STORES_TAB);
      return PAGES_KEY_MANAGEMENT_INDEX;
    }

    EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                      .orElse(new EidasMiddlewareConfig());
    EidasMiddlewareConfig.KeyData keyData = Optional.ofNullable(eidasMiddlewareConfig.getKeyData())
                                                    .orElse(new EidasMiddlewareConfig.KeyData());
    keyData.getKeyStore()
           .add(new KeyStoreType(keyStoreUploadModel.getName(), keyStoreFileBytes,
                                 KeyStoreTypeType.fromValue(keyStoreUploadModel.getKeyStoreType().replace("_", "")),
                                 keyStoreUploadModel.getPassword()));
    eidasMiddlewareConfig.setKeyData(keyData);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Key store saved: " + keyStoreUploadModel.getName());
    return REDIRECT_TO_INDEX;
  }

  /**
   * Upload a new certificate.
   */
  @PostMapping("/uploadCertificate")
  public String uploadCertificate(Model model,
                                  @ModelAttribute @Valid CertificateUploadModel certificateUploadModel,
                                  BindingResult bindingResult,
                                  @RequestParam("certificateFile") MultipartFile certificateFile,
                                  RedirectAttributes redirectAttributes)
  {

    if (getCertificates().parallelStream()
                         .anyMatch(k -> k.getName().equalsIgnoreCase(certificateUploadModel.getName())))
    {
      bindingResult.addError(new FieldError(CERTIFICATE_UPLOAD_MODEL, "name", THIS_NAME_IS_ALREADY_TAKEN));
    }

    if (certificateFile.isEmpty())
    {
      bindingResult.addError(new ObjectError(CERTIFICATE_UPLOAD_MODEL, "Please select a file"));

    }

    byte[] certificateFileBytes = null;
    try
    {
      certificateFileBytes = certificateFile.getBytes();
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      final X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificateFileBytes)); // NOPMD
    }
    catch (CertificateException e)
    {
      bindingResult.addError(new ObjectError(CERTIFICATE_UPLOAD_MODEL,
                                             "Could not parse uploaded certificate into X.509"));
    }
    catch (IOException e)
    {
      bindingResult.addError(new ObjectError(CERTIFICATE_UPLOAD_MODEL, "Could not read uploaded certificate"));
    }

    if (bindingResult.hasErrors())
    {
      model.addAttribute(KEY_STORE_UPLOAD_MODEL, new KeystoreUploadModel());
      model.addAttribute(KEY_STORE_INFO_LIST, getKeyStores());
      model.addAttribute(CERTIFICATES, getCertificates());
      model.addAttribute(KEY_PAIRS, getKeyPairs());
      model.addAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);
      return PAGES_KEY_MANAGEMENT_INDEX;
    }

    EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                      .orElse(new EidasMiddlewareConfig());
    EidasMiddlewareConfig.KeyData keyData = Optional.ofNullable(eidasMiddlewareConfig.getKeyData())
                                                    .orElse(new EidasMiddlewareConfig.KeyData());
    keyData.getCertificate()
           .add(new CertificateType(certificateUploadModel.getName(), certificateFileBytes, null, null));
    eidasMiddlewareConfig.setKeyData(keyData);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);
    redirectAttributes.addFlashAttribute("msg", "Certificated saved: " + certificateUploadModel.getName());
    return REDIRECT_TO_INDEX;
  }


  /**
   * Extract a key pair from a saved key store.
   */
  @PostMapping("/createCertificateOrKeyFromKeystore/createKeypair")
  public String createKeypairFromKeystore(Model model,
                                          @ModelAttribute @Valid CreateKeypairFromKeystoreModel createKeypairFromKeystoreModel,
                                          BindingResult bindingResult,
                                          @RequestParam("keystorename") String keyStoreName,
                                          RedirectAttributes redirectAttributes)
  {

    final Optional<KeyStoreType> keyStoreTypeOptional = configurationService.getConfiguration()
                                                                            .stream()
                                                                            .map(EidasMiddlewareConfig::getKeyData)
                                                                            .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                                                                            .flatMap(List::stream)
                                                                            .filter(k -> createKeypairFromKeystoreModel.getKeystore()
                                                                                                                       .equals(k.getName()))
                                                                            .findFirst();
    // Check if key store exists
    if (keyStoreTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, KEY_STORE + keyStoreName + COULD_NOT_BE_FOUND);
      return REDIRECT_TO_INDEX;
    }

    // Check if name is taken
    if (getKeyPairs().parallelStream()
                     .anyMatch(k -> k.getName().equalsIgnoreCase(createKeypairFromKeystoreModel.getName())))
    {
      bindingResult.addError(new FieldError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, "name", THIS_NAME_IS_ALREADY_TAKEN));
    }

    // Open key store
    final KeyStoreType keyStoreType = keyStoreTypeOptional.get();

    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                          .value()),
                                                       keyStoreType.getPassword());

    // Check if key pair exists
    try
    {
      if (!keyStore.isKeyEntry(createKeypairFromKeystoreModel.getAlias()))
      {
        bindingResult.addError(new FieldError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, ALIAS, "Alias is not a key pair"));
      }
    }
    catch (KeyStoreException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Could not open key store " + createKeypairFromKeystoreModel.getKeystore(), e);
      }
      bindingResult.addError(new ObjectError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, COULD_NOT_READ_KEY_STORE));
    }

    try
    {
      keyStore.getKey(createKeypairFromKeystoreModel.getAlias(),
                      createKeypairFromKeystoreModel.getPassword() == null ? new char[0]
                        : createKeypairFromKeystoreModel.getPassword().toCharArray());
    }
    catch (KeyStoreException e)
    {
      log.debug(COULD_NOT_LOAD_KEY, e);
      bindingResult.addError(new ObjectError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, COULD_NOT_READ_KEY_STORE));
    }
    catch (NoSuchAlgorithmException e)
    {
      log.debug(COULD_NOT_LOAD_KEY, e);
      bindingResult.addError(new ObjectError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, "Could not read key pair"));
    }
    catch (UnrecoverableKeyException e)
    {
      log.debug(COULD_NOT_LOAD_KEY, e);
      bindingResult.addError(new FieldError(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, "password",
                                            "Password could be wrong"));
    }


    if (bindingResult.hasErrors())
    {
      model.addAttribute(KEY_STORE_INFO, keydataKeyStoreToInfoHolder(keyStoreType));
      model.addAttribute(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, new CreateCertificateFromKeystoreModel());
      model.addAttribute(CERTIFICATES, getCertificates());
      model.addAttribute(KEY_PAIRS, getKeyPairs());
      model.addAttribute(KEY_STORE_INFO_LIST, getKeyStores());
      return PAGES_KEY_MANAGEMENT_CREATE_FROM_KEY_STORE;
    }

    EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                      .orElse(new EidasMiddlewareConfig());
    EidasMiddlewareConfig.KeyData keyData = Optional.ofNullable(eidasMiddlewareConfig.getKeyData())
                                                    .orElse(new EidasMiddlewareConfig.KeyData());
    keyData.getKeyPair()
           .add(new KeyPairType(createKeypairFromKeystoreModel.getName(), createKeypairFromKeystoreModel.getAlias(),
                                createKeypairFromKeystoreModel.getPassword(),
                                createKeypairFromKeystoreModel.getKeystore()));

    eidasMiddlewareConfig.setKeyData(keyData);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_PAIRS_TAB);
    redirectAttributes.addFlashAttribute("msg", "Key pair created: " + createKeypairFromKeystoreModel.getName());
    return REDIRECT_TO_INDEX;
  }

  /**
   * Extract a certificate from a saved key store.
   */
  @PostMapping("/createCertificateOrKeyFromKeystore/createCertificate")
  public String createCertificateFromKeystore(Model model,
                                              @ModelAttribute @Valid CreateCertificateFromKeystoreModel createCertificateFromKeystoreModel,
                                              BindingResult bindingResult,
                                              @RequestParam("keystorename") String keyStoreName,
                                              RedirectAttributes redirectAttributes)
  {

    final Optional<KeyStoreType> keyStoreTypeOptional = configurationService.getConfiguration()
                                                                            .stream()
                                                                            .map(EidasMiddlewareConfig::getKeyData)
                                                                            .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                                                                            .flatMap(List::stream)
                                                                            .filter(k -> createCertificateFromKeystoreModel.getKeystore()
                                                                                                                           .equals(k.getName()))
                                                                            .findFirst();
    // Check if key store exsists
    if (keyStoreTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, KEY_STORE + keyStoreName + COULD_NOT_BE_FOUND);
      return REDIRECT_TO_INDEX;
    }

    // Check if name is taken
    if (getCertificates().parallelStream()
                         .anyMatch(k -> k.getName().equalsIgnoreCase(createCertificateFromKeystoreModel.getName())))
    {
      bindingResult.addError(new FieldError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, "name",
                                            THIS_NAME_IS_ALREADY_TAKEN));
    }

    // Open key store
    final KeyStoreType keyStoreType = keyStoreTypeOptional.get();

    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                       KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                          .value()),
                                                       keyStoreType.getPassword());

    // Check if key pair exists
    try
    {
      if (!(keyStore.isCertificateEntry(createCertificateFromKeystoreModel.getAlias())
            || keyStore.isKeyEntry(createCertificateFromKeystoreModel.getAlias())))
      {
        bindingResult.addError(new FieldError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, ALIAS,
                                              "Alias is not a certificate"));
      }
    }
    catch (KeyStoreException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Could not open key store " + createCertificateFromKeystoreModel.getKeystore(), e);
      }
      bindingResult.addError(new ObjectError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, COULD_NOT_READ_KEY_STORE));
    }

    byte[] certificateBytes = null;
    try
    {
      Certificate certificate = keyStore.getCertificate(createCertificateFromKeystoreModel.getAlias());
      if (certificate == null)
      {
        bindingResult.addError(new FieldError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, ALIAS,
                                              "No certificate found for alias"));
      }
      else
      {
        certificateBytes = certificate.getEncoded();
      }
    }
    catch (KeyStoreException e)
    {
      log.debug(COULD_NOT_LOAD_KEY, e);
      bindingResult.addError(new ObjectError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, COULD_NOT_READ_KEY_STORE));
    }
    catch (CertificateEncodingException e)
    {
      log.debug("Could not encode certificate", e);
      bindingResult.addError(new ObjectError(CREATE_CERTIFICATE_FROM_KEYSTORE_MODEL, "Could not read certificate"));
    }


    if (bindingResult.hasErrors())
    {
      model.addAttribute(KEY_STORE_INFO, keydataKeyStoreToInfoHolder(keyStoreType));
      model.addAttribute(CREATE_KEY_PAIR_FROM_KEY_STORE_MODEL, new CreateKeypairFromKeystoreModel());
      model.addAttribute(CERTIFICATES, getCertificates());
      model.addAttribute(KEY_PAIRS, getKeyPairs());
      model.addAttribute(KEY_STORE_INFO_LIST, getKeyStores());
      return PAGES_KEY_MANAGEMENT_CREATE_FROM_KEY_STORE;
    }

    EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration()
                                                                      .orElse(new EidasMiddlewareConfig());
    EidasMiddlewareConfig.KeyData keyData = Optional.ofNullable(eidasMiddlewareConfig.getKeyData())
                                                    .orElse(new EidasMiddlewareConfig.KeyData());
    keyData.getCertificate()
           .add(new CertificateType(createCertificateFromKeystoreModel.getName(), certificateBytes,
                                    createCertificateFromKeystoreModel.getKeystore(),
                                    createCertificateFromKeystoreModel.getAlias()));

    eidasMiddlewareConfig.setKeyData(keyData);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);
    redirectAttributes.addFlashAttribute("msg", "Certificate created: " + createCertificateFromKeystoreModel.getName());
    return REDIRECT_TO_INDEX;
  }


  @GetMapping("/deleteKeyStore")
  public String deleteKeystore(Model model, @RequestParam("keystorename") String keyStoreName, RedirectAttributes redirectAttributes)
  {

    final Optional<KeyStoreType> keyStoreTypeOptional = findKeystoreTypeByName(keyStoreName);

    if (!checkIfKeystoreMayBeDeleted(keyStoreName, redirectAttributes, keyStoreTypeOptional))
    {
      redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_STORES_TAB);
      return REDIRECT_TO_INDEX;
    }

    model.addAttribute("keystorename", keyStoreName);
    return "pages/keymanagement/deleteKeystore";
  }

  private boolean checkIfKeystoreMayBeDeleted(String keyStoreName,
                                              RedirectAttributes redirectAttributes,
                                              Optional<KeyStoreType> keyStoreTypeOptional)
  {
    if (keyStoreTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, "Key store not found: " + keyStoreName);
      return false;
    }

    final Set<CertificateType> referencingCertificates = configurationService.getCertificateTypes()
                                                                             .parallelStream()
                                                                             .filter(c -> keyStoreName.equals(c.getKeystore()))
                                                                             .collect(Collectors.toSet());

    if (!referencingCertificates.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Key store " + keyStoreName
                                                  + " can not be removed. Following certificates are referencing the key store: "
                                                  + referencingCertificates.stream()
                                                                           .map(CertificateType::getName)
                                                                           .collect(Collectors.joining(", ")));
      return false;
    }

    final Set<KeyPairType> referencingKeyPairs = configurationService.getKeyPairTypes()
                                                                     .parallelStream()
                                                                     .filter(c -> keyStoreName.equals(c.getKeyStoreName()))
                                                                     .collect(Collectors.toSet());

    if (!referencingKeyPairs.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Key store " + keyStoreName
                                                  + " can not be removed. Following key pairs are referencing the key store: "
                                                  + referencingKeyPairs.stream()
                                                                       .map(KeyPairType::getName)
                                                                       .collect(Collectors.joining(", ")));
      return false;
    }
    return true;
  }

  @PostMapping("/deleteKeyStore")
  public String deleteKeystoreConfirmed(@RequestParam("keystorename") String keyStoreName, RedirectAttributes redirectAttributes)
  {

    final Optional<KeyStoreType> keyStoreTypeOptional = findKeystoreTypeByName(keyStoreName);
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_STORES_TAB);

    if (!checkIfKeystoreMayBeDeleted(keyStoreName, redirectAttributes, keyStoreTypeOptional))
    {
      return REDIRECT_TO_INDEX;
    }


    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration().get(); // Can not be
                                                                                                       // empty
    eidasMiddlewareConfig.getKeyData()
                         .getKeyStore()
                         .removeIf(k -> k.getName().equals(keyStoreTypeOptional.get().getName()));
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Key store removed: " + keyStoreName);
    return REDIRECT_TO_INDEX;


  }

  private Optional<KeyStoreType> findKeystoreTypeByName(String keyStoreName)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                               .stream()
                               .flatMap(List::stream)
                               .filter(k -> k.getName().equals(keyStoreName))
                               .findFirst();
  }

  @GetMapping("/deleteCertificate")
  public String deleteCertificate(Model model, @RequestParam("certificatename") String name, RedirectAttributes redirectAttributes)
  {
    final Optional<CertificateType> certificateTypeOptional = findCertificateTypeByName(name);

    if (certificateTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);
      redirectAttributes.addFlashAttribute(ERROR, "Certificate not found: " + name);
      return REDIRECT_TO_INDEX;
    }


    if (configKeyDataService.isCertificateReferenced(name))
    {
      redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Certificate " + name + " is used in configuration and can not be removed");
      return REDIRECT_TO_INDEX;
    }



    model.addAttribute("name", name);
    return "pages/keymanagement/deleteCertificate";
  }

  @PostMapping("/deleteCertificate")
  public String deleteCertificateConfirmed(@RequestParam("certificatename") String name, RedirectAttributes redirectAttributes)
  {
    final Optional<CertificateType> certificateTypeOptional = findCertificateTypeByName(name);
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, CERTIFICATES_TAB);

    if (certificateTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, "Certificate not found: " + name);
      return REDIRECT_TO_INDEX;
    }

    if (configKeyDataService.isCertificateReferenced(name))
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Certificate " + name + " is used in configuration and can not be removed");
      return REDIRECT_TO_INDEX;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration().get(); // Can not be
                                                                                                       // empty
    eidasMiddlewareConfig.getKeyData()
                         .getCertificate()
                         .removeIf(k -> k.getName().equals(certificateTypeOptional.get().getName()));
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);
    redirectAttributes.addFlashAttribute("msg", "Certificate removed: " + name);
    return REDIRECT_TO_INDEX;
  }

  private Optional<CertificateType> findCertificateTypeByName(String name)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getCertificate)
                               .stream()
                               .flatMap(List::stream)
                               .filter(c -> c.getName().equals(name))
                               .findFirst();
  }

  @GetMapping("/deleteKeypair")
  public String deleteKeypair(Model model, @RequestParam("keypairname") String name, RedirectAttributes redirectAttributes)
  {
    final Optional<KeyPairType> keyPairTypeOptional = findKeyPairTypeByName(name);

    if (keyPairTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_PAIRS_TAB);
      redirectAttributes.addFlashAttribute(ERROR, "Key pair not found: " + name);
      return REDIRECT_TO_INDEX;
    }

    if (configKeyDataService.isKeyPairReferenced(name))
    {
      redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_PAIRS_TAB);
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Key pair " + name + " is used in configuration and can not be removed");
      return REDIRECT_TO_INDEX;
    }

    model.addAttribute("name", name);
    return "pages/keymanagement/deleteKeypair";
  }

  @PostMapping("/deleteKeypair")
  public String deleteKeypairConfirmed(Model model, @RequestParam("keypairname") String name, RedirectAttributes redirectAttributes)
  {
    final Optional<KeyPairType> keyPairTypeOptional = findKeyPairTypeByName(name);
    redirectAttributes.addFlashAttribute(JUMP_TO_TAB, KEY_PAIRS_TAB);

    if (keyPairTypeOptional.isEmpty())
    {
      redirectAttributes.addFlashAttribute(ERROR, "Key pair not found: " + name);
      return REDIRECT_TO_INDEX;
    }

    if (configKeyDataService.isKeyPairReferenced(name))
    {
      redirectAttributes.addFlashAttribute(ERROR,
                                           "Key pair " + name + " is used in configuration and can not be removed");
      return REDIRECT_TO_INDEX;
    }

    final EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration().get(); // Can not be
                                                                                                       // empty
    eidasMiddlewareConfig.getKeyData()
                         .getKeyPair()
                         .removeIf(k -> k.getName().equals(keyPairTypeOptional.get().getName()));
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    redirectAttributes.addFlashAttribute("msg", "Key pair removed: " + name);
    return REDIRECT_TO_INDEX;
  }

  private Optional<KeyPairType> findKeyPairTypeByName(String name)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getKeyPair)
                               .stream()
                               .flatMap(List::stream)
                               .filter(c -> c.getName().equals(name))
                               .findFirst();
  }


  private Optional<KeystoreInfoHolder> getKeystoreInfoHolder(String keyStoreName)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getKeyData)
                               .map(EidasMiddlewareConfig.KeyData::getKeyStore)
                               .stream()
                               .flatMap(List::stream)
                               .filter(l -> keyStoreName.equals(l.getName()))
                               .map(this::keydataKeyStoreToInfoHolder)
                               .findFirst();
  }

}
