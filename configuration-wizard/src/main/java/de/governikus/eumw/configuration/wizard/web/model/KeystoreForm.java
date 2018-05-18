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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.exceptions.CertificateException;
import de.governikus.eumw.configuration.wizard.exceptions.InvalidKeystoreException;
import de.governikus.eumw.configuration.wizard.exceptions.KeystoreException;
import de.governikus.eumw.configuration.wizard.exceptions.WrongAliasException;
import de.governikus.eumw.configuration.wizard.exceptions.WrongPasswordException;
import de.governikus.eumw.configuration.wizard.web.handler.NamedObject;
import de.governikus.eumw.configuration.wizard.web.utils.ExceptionHelper;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.exceptions.CertificateCreationException;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import de.governikus.eumw.utils.key.exceptions.KeyStoreReadingException;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 09.02.2018 - 13:37 <br>
 * <br>
 * a html view form that represents some keystore information
 */
@Slf4j
@ToString(exclude = {"keystore"})
@Data
@NoArgsConstructor
public class KeystoreForm implements NamedObject
{

  /**
   * the name of this keystore file that will be displayed in selections in the view
   */
  @NotBlank(message = "Name must not be empty.")
  private String keystoreName;

  /**
   * the keystore file that was uploaded
   */
  @NotNull(message = "File must not be empty.")
  private MultipartFile keystoreFile;

  /**
   * the alias of the keystore entry that should be accessed
   */
  @NotBlank(message = "Alias must not be empty.")
  private String alias;

  /**
   * the password to open the keystore
   */
  private String keystorePassword;

  /**
   * the password to access the given private key for the given {@link #alias} inside the keystore
   */
  private String privateKeyPassword;

  /**
   * this is the java representation of {@link #keystoreFile}
   */
  private transient KeyStore keystore;

  /**
   * lombok builder constructor
   */
  @Builder
  public KeystoreForm(String keystoreName,
                      MultipartFile keystoreFile,
                      String alias,
                      String keystorePassword,
                      String privateKeyPassword,
                      KeyStore keystore)
  {
    this.keystoreName = keystoreName;
    this.keystoreFile = keystoreFile;
    this.alias = alias;
    this.keystorePassword = keystorePassword;
    this.privateKeyPassword = privateKeyPassword;
    this.keystore = keystore;
  }

  /**
   * @see #keystore
   */
  public KeyStore getKeystore()
  {
    initializeKeystore();
    return keystore;
  }

  /**
   * @return the private key entry of this keystore
   */
  public PrivateKey getPrivateKey()
  {
    try
    {
      PrivateKey privateKey = (PrivateKey)getKeystore().getKey(alias, privateKeyPassword.toCharArray());
      if (privateKey == null)
      {
        log.warn("could not access private key of keystore '{}' with alias '{}'", keystoreName, alias);
      }
      return privateKey;
    }
    catch (UnrecoverableKeyException e)
    {
      throw new KeystoreException("could not extract key from keystore with name '" + getName()
                                  + "' and alias '" + alias + "'", e);
    }
    catch (NoSuchAlgorithmException | KeyStoreException e)
    {
      throw new KeystoreException(e.getMessage(), e);
    }
  }

  /**
   * @return the {@link X509Certificate} of the keystore entry with the given {@link #alias}
   */
  public X509Certificate getX509Certificate()
  {
    try
    {
      X509Certificate certificate = (X509Certificate)getKeystore().getCertificate(alias);
      if (certificate == null)
      {
        log.warn("could not read certificate entry of keystore '{}' with alias '{}'", keystoreName, alias);
      }
      return certificate;
    }
    catch (KeyStoreException e)
    {
      throw new CertificateException("could not extract X509 certificate from keystore with name '"
                                     + getName() + "' " + "and alias '" + alias + "'" + "", e);
    }
  }

  /**
   * will initialize the {@link #keystore}
   */
  public void initializeKeystore()
  {
    if (keystore == null && keystoreFile != null)
    {
      // @formatter:off
      KeyStoreSupporter.KeyStoreType keyStoreType =
           KeyStoreSupporter.KeyStoreType.byFileExtension(keystoreFile.getOriginalFilename())
                                                                      .orElse(KeyStoreSupporter.KeyStoreType.JKS);
      // @formatter:on
      try
      {
        keystore = KeyStoreSupporter.readKeyStore(keystoreFile.getBytes(), keyStoreType, keystorePassword);
      }
      catch (KeyStoreCreationFailedException ex)
      {
        Throwable root = ExceptionUtils.getRootCause(ex);
        if (root == null || !UnrecoverableKeyException.class.isAssignableFrom(root.getClass()))
        {
          throw ex;
        }
        else
        {
          throw new WrongPasswordException("keystore password seems to be incorrect", ex);
        }
      }
      catch (IOException e)
      {
        throw new KeyStoreCreationFailedException("could not open keystore from file '"
                                                  + keystoreFile.getOriginalFilename() + "': "
                                                  + e.getMessage(), e);
      }

      checkPrivateKeyPassword();
    }
  }

  /**
   * This method checks if the given key password or the keystore password are valid to get the key
   */
  private void checkPrivateKeyPassword()
  {
    try
    {
      if (keystore.getKey(alias, privateKeyPassword.toCharArray()) == null)
      {
        throw new WrongAliasException("alias '" + alias
                                      + "' is not present in the keystore. Valid aliases are: '"
                                      + getValidAliasesAsList() + "'");
      }
    }
    catch (KeyStoreException | NoSuchAlgorithmException e)
    {
      throw new InvalidKeystoreException("could not access private key of keystore", e);
    }
    catch (UnrecoverableKeyException e)
    {
      try
      {
        keystore.getKey(alias, keystorePassword.toCharArray());
        this.privateKeyPassword = keystorePassword;
      }
      catch (KeyStoreException | NoSuchAlgorithmException e1)
      {
        throw new InvalidKeystoreException("could not access private key of keystore", e);
      }
      catch (UnrecoverableKeyException e1)
      {
        throw new WrongPasswordException("private key could not be extracted, please check your password",
                                         e1);
      }
    }
  }

  /**
   * translates this keystore-form to a certificate-form that will be used to be displayed on the html view
   *
   * @return the translated certificate form
   */
  public CertificateForm asCertificate()
  {
    CertificateForm certificateForm = new CertificateForm();
    try
    {
      certificateForm.setCertificateName(keystoreName);
      certificateForm.setCertificate((X509Certificate)getKeystore().getCertificate(alias));
    }
    catch (KeyStoreException e)
    {
      throw new CertificateCreationException("could not read certificate entry '" + alias + "' from keystore",
                                             e);
    }
    return certificateForm;
  }

  /**
   * will return all aliases as list. <br>
   * this is just a convenience method to prevent handling with {@link KeyStoreException}
   */
  public List<String> getValidAliasesAsList()
  {
    try
    {
      Enumeration<String> aliasEnumeration = keystore.aliases();
      List<String> aliases = new ArrayList<>();
      while (aliasEnumeration.hasMoreElements())
      {
        aliases.add(aliasEnumeration.nextElement());
      }
      return aliases;
    }
    catch (KeyStoreException e)
    {
      throw new KeyStoreReadingException("could not access the given keystore", e);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String getName()
  {
    return keystoreName;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean isValid()
  {
    boolean isValid;
    try
    {
      isValid = getX509Certificate() != null;
    }
    catch (CertificateException ex)
    {
      log.error("could not read certificate for: '{}'", ExceptionHelper.getRootMessage(ex));
      isValid = false;
    }

    try
    {
      boolean privateKeyAccessible = getPrivateKey() != null;
      isValid = isValid && privateKeyAccessible;
    }
    catch (KeystoreException ex)
    {
      log.error("could not read private key for: '{}'", ExceptionHelper.getRootMessage(ex));
      isValid = false;
    }
    return isValid;
  }
}
