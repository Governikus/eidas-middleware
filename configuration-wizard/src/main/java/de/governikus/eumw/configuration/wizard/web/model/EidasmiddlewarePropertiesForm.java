/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Optional;
import java.util.Properties;
import java.util.TreeSet;

import javax.validation.constraints.NotBlank;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.DeferredFileOutputStream;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.commons.CommonsMultipartFile;

import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.identifier.MiddlewarePropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.web.utils.ExceptionHelper;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 09:43 <br>
 * <br>
 * this class will represent the form for the view that is used to befill the eidasmiddleware.properties
 */
@Slf4j
@Data
public class EidasmiddlewarePropertiesForm extends AbstractPropertiesConfigurationLoader
{

  /**
   * folder name where the serviceprovider metadata file is stored
   */
  private static final String SERVICEPROVIDER_METADATA_FOLDERNAME = "serviceprovider-metadata";

  /**
   * this file represents an uploaded preconfigured file that the user might have uploaded or loaded with the
   * system-start
   */
  private MultipartFile eidasPropertiesFile;

  /**
   * service provider metadata
   */
  private String serviceProviderMetadataPath;

  /**
   * service provider metadata
   */
  private MultipartFile serviceProviderMetadataFile;

  /**
   * Because spring deletes the temporary MultipartFiles before we save them we must keep them in memory.
   *
   * @see #serviceProviderMetadataFile
   */
  private byte[] serviceProviderMetadataFileBytes;

  /**
   * certificate the metadata is signed with
   */
  private CertificateForm metadataSignatureCertificate;

  /**
   * EntityID of the corresponding service provider in POSeIDAS.xml
   */
  private String entityIdInt;

  /**
   * The serverURL of the middleware, must match with the URLs in the POSeIDAS.xml
   */
  private String serverURL;

  /**
   * keystore containing the middleware signature keypair
   */
  private KeystoreForm middlewareSignKeystore;

  /**
   * keystore containing the middleware crypto keypair
   */
  private KeystoreForm middlewareCryptKeystore;

  /**
   * country where the MW is deployed
   */
  @NotBlank
  private String countryCode;

  // ********************************* contact details **************************************
  @NotBlank
  private String contactPersonCompany;

  @NotBlank
  private String contactPersonEmail;

  @NotBlank
  private String contactPersonGivenname;

  @NotBlank
  private String contactPersonSurname;

  @NotBlank
  private String contactPersonTel;

  @NotBlank
  private String organizationDisplayName;

  @NotBlank
  private String organizationName;

  @NotBlank
  private String organizationUrl;

  @NotBlank
  private String organizationLang;

  /**
   * {@inheritDoc}
   */
  @Override
  void readFromProperties(Properties middlewareProperties)
  {
    // @formatter:off
    this.serviceProviderMetadataPath =
              (String) middlewareProperties.get(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name());
    // @formatter:on
    getServiceProviderMetadataFile(middlewareProperties).ifPresent(this::setServiceProviderMetadataFile);
    loadMetadataSignatureCertificate(middlewareProperties).ifPresent(this::setMetadataSignatureCertificate);
    this.entityIdInt = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.ENTITYID_INT.name());
    this.serverURL = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.SERVER_URL.name());
    // @formatter:off
    String keystorePath =
                      (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_KEY.name());
    String keystoreAlias =
                      (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name());
    String keystorePassword =
                      (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name());
    String privateKeyPassword = keystorePassword;
    // @formatter:on
    loadKeystoreSettings("eidasmw-signature-keystore",
                         keystorePath,
                         null,
                         keystoreAlias,
                         keystorePassword,
                         privateKeyPassword).ifPresent(this::setMiddlewareSignKeystore);

    // @formatter:off
    keystorePath = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name());
    keystoreAlias = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name());
    keystorePassword = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name());
    privateKeyPassword = keystorePassword;
    // @formatter:on
    loadKeystoreSettings("eidasmw-crypto-keystore",
                         keystorePath,
                         null,
                         keystoreAlias,
                         keystorePassword,
                         privateKeyPassword).ifPresent(this::setMiddlewareCryptKeystore);

    this.countryCode = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.COUNTRYCODE.name());

    // @formatter:off
    this.contactPersonCompany =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name());
    this.contactPersonEmail =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name());
    this.contactPersonGivenname =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name());
    this.contactPersonSurname =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name());
    this.contactPersonTel =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name());

    this.organizationDisplayName =
              (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name());
    this.organizationName = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name());
    this.organizationUrl = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name());
    this.organizationLang = (String)middlewareProperties.get(MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name());
    // @formatter:on
  }

  /**
   * tries to access the metadata signature certificate from the properties file and will translate it into a
   * {@link CertificateForm}
   *
   * @param properties the properties with a possible reference to the certificate
   * @return en empty if the reference does not exist or the reference does not point to a valid location or a
   *         valid certificate, the {@link CertificateForm} else
   */
  private Optional<CertificateForm> loadMetadataSignatureCertificate(Properties properties)
  {
    // @formatter:off
    String metadataSignatureCertPath =
              (String)properties.get(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name());
    // @formatter:on
    if (StringUtils.isNotBlank(metadataSignatureCertPath))
    {
      File signatureCertFile = new File(metadataSignatureCertPath);
      if (signatureCertFile.exists())
      {
        try (InputStream inputStream = new FileInputStream(signatureCertFile))
        {
          return getCertificate("metadata-signature-certificate", IOUtils.toByteArray(inputStream));
        }
        catch (IOException e)
        {
          log.warn(e.getMessage(), e);
        }
      }
    }
    return Optional.empty();
  }

  /**
   * tries to read the service provider metadata file as multipart file
   *
   * @param properties the properties with the possible location of the metadata file
   * @return the file as multipart file if it exists
   */
  private Optional<MultipartFile> getServiceProviderMetadataFile(Properties properties)
  {
    // @formatter:off
    String serviceProviderMetadataPathTmp =
                (String) properties.get(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name());
    // @formatter:on
    if (StringUtils.isBlank(serviceProviderMetadataPathTmp))
    {
      log.warn("empty path for service provider meta-data file under eidas middleware property '{}'",
               MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name());
      return Optional.empty();
    }
    File metadataDirectory = new File(serviceProviderMetadataPathTmp);
    if (!metadataDirectory.exists())
    {
      log.warn("service provider metadata file does not exist at location '{}'",
               metadataDirectory.getAbsolutePath());
      return Optional.empty();
    }
    File[] files = metadataDirectory.listFiles();
    Optional<File> optionalFile = Arrays.stream(files)
                                        .filter(file -> file.getName().endsWith(".xml"))
                                        .findFirst();
    if (optionalFile.isPresent())
    {
      File metadataFile = optionalFile.get();
      FileItem uploadedFileMock = new DiskFileItem("eidasmiddlewareProperties.serviceProviderMetadataFile",
                                                   MediaType.APPLICATION_XML_VALUE, true,
                                                   metadataFile.getName(), Integer.MAX_VALUE, null);
      try (
        DeferredFileOutputStream outputStream = (DeferredFileOutputStream)uploadedFileMock.getOutputStream();
        FileInputStream fileInputStream = new FileInputStream(metadataFile))
      {
        // will write the metadata-file into a temporary file in the "java.io.tmpdir"-directory this is
        // necessary to have access to the inputstream when saving the file in a new location
        outputStream.write(IOUtils.toByteArray(fileInputStream));
      }
      catch (IOException ex)
      {
        log.error("problem while initializing outputstream for uploaded mock file: {}",
                  ExceptionHelper.getRootMessage(ex));
      }
      return Optional.of(new CommonsMultipartFile(uploadedFileMock));
    }
    else
    {
      return Optional.empty();
    }
  }

  /**
   * save the eidas middleware properties form into directory/eidasmiddleware.properties file
   *
   * @param directory file path
   * @throws IOException
   * @throws CertificateEncodingException
   */
  public void save(String directory) throws IOException, CertificateEncodingException
  {
    KeyStoreSupporter.keyStoreToFile(new File(directory),
                                     middlewareSignKeystore.getKeystoreName(),
                                     middlewareSignKeystore.getKeystore(),
                                     middlewareSignKeystore.getKeystorePassword());
    KeyStoreSupporter.keyStoreToFile(new File(directory),
                                     middlewareCryptKeystore.getKeystoreName(),
                                     middlewareCryptKeystore.getKeystore(),
                                     middlewareCryptKeystore.getKeystorePassword());

    Files.createDirectories(Paths.get(directory, SERVICEPROVIDER_METADATA_FOLDERNAME));
    FileUtils.cleanDirectory(Paths.get(directory,
            SERVICEPROVIDER_METADATA_FOLDERNAME).toFile());
    Files.write(Paths.get(directory,
                          SERVICEPROVIDER_METADATA_FOLDERNAME,
                          serviceProviderMetadataFile.getOriginalFilename()),
                serviceProviderMetadataFileBytes);

    Files.write(Paths.get(directory, metadataSignatureCertificate.getName() + ".crt"),
                metadataSignatureCertificate.getCertificate().getEncoded());

    Properties properties = toProperties(directory);
    File file = Paths.get(directory, FileNames.MIDDLEWARE_PROPERTIES.getFileName()).toFile();
    try (FileOutputStream fileOut = new FileOutputStream(file))
    {
      properties.store(fileOut, null);
    }
  }

  /**
   * maps the {@link EidasmiddlewarePropertiesForm} to {@link Properties}
   */
  public Properties toProperties(String pathPrefix)
  {
    Properties properties = new Properties()
    {

      @Override
      public synchronized Enumeration<Object> keys()
      {
        return Collections.enumeration(new TreeSet<>(super.keySet()));
      }
    };

    properties.setProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name(),
                           addPathPrefix(pathPrefix, SERVICEPROVIDER_METADATA_FOLDERNAME));
    properties.setProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name(),
                           addPathPrefix(pathPrefix, metadataSignatureCertificate.getName() + ".crt"));
    properties.setProperty(MiddlewarePropertiesIdentifier.ENTITYID_INT.name(), entityIdInt);
    properties.setProperty(MiddlewarePropertiesIdentifier.SERVER_URL.name(), serverURL);
    // @formatter:off
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_KEY.name(),
                           addPathPrefix(pathPrefix,
                             middlewareSignKeystore.getKeystoreName() + "."
                                         + KeyStoreSupporter.KeyStoreType.valueOf(middlewareSignKeystore.getKeystore()
                                                                                                        .getType())
                                                                         .getFileExtension()));
    // @formatter:on
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name(),
                           middlewareSignKeystore.getKeystorePassword());
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name(),
                           middlewareSignKeystore.getAlias());
    // @formatter:off
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name(),
                           addPathPrefix(pathPrefix,
                             middlewareCryptKeystore.getKeystoreName() + "."
                                         + KeyStoreSupporter.KeyStoreType.valueOf(middlewareCryptKeystore.getKeystore()
                                                                                                         .getType())
                                                                         .getFileExtension()));
    // @formatter:on
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name(),
                           middlewareCryptKeystore.getKeystorePassword());
    properties.setProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name(),
                           middlewareCryptKeystore.getAlias());
    properties.setProperty(MiddlewarePropertiesIdentifier.COUNTRYCODE.name(), countryCode);
    properties.setProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name(),
                           contactPersonCompany);
    properties.setProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name(), contactPersonEmail);
    properties.setProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name(),
                           contactPersonGivenname);
    properties.setProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name(),
                           contactPersonSurname);
    properties.setProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name(), contactPersonTel);
    properties.setProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name(),
                           organizationDisplayName);
    properties.setProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name(), organizationName);
    properties.setProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name(), organizationUrl);
    properties.setProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name(), organizationLang);

    return properties;
  }

  private String addPathPrefix(String pathPrefix, String filename)
  {
    return Paths.get(pathPrefix, filename).toString().replace("\\", "/");
  }

  /**
   * @see #serviceProviderMetadataFile
   */
  public void setServiceProviderMetadataFile(MultipartFile serviceProviderMetadataFile)
  {
    if (serviceProviderMetadataFile != null && serviceProviderMetadataFile.getSize() > 0)
    {
      this.serviceProviderMetadataFile = serviceProviderMetadataFile;
      try
      {
        this.serviceProviderMetadataFileBytes = serviceProviderMetadataFile.getBytes();
      }
      catch (IOException e)
      {
        throw new IllegalStateException("Cannot load bytes from file: "
                                        + serviceProviderMetadataFile.getOriginalFilename(), e);
      }
    }
  }

  /**
   * @see #eidasPropertiesFile
   */
  public void setEidasPropertiesFile(MultipartFile eidasPropertiesFile)
  {
    this.eidasPropertiesFile = eidasPropertiesFile;
    if (eidasPropertiesFile != null && !eidasPropertiesFile.isEmpty())
    {
      loadConfiguration(eidasPropertiesFile);
    }
  }
}
