/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import java.util.function.Consumer;

import de.governikus.eumw.configuration.wizard.exceptions.CertificateException;
import de.governikus.eumw.configuration.wizard.exceptions.KeystoreException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 14.02.2018 - 10:56 <br>
 * <br>
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SettingsHelper
{

  /**
   * a funtional template for setting certificate values to a specific byte[] field
   *
   * @param certificateForm the certificate that should set to the byte[] field
   * @param setValue the method call that will set the bytes to the desired field
   */
  public static void addCertificateToField(CertificateForm certificateForm, Consumer<byte[]> setValue)
  {
    if (certificateForm == null || certificateForm.getCertificateFile() == null
        || certificateForm.getCertificateFile().getSize() == 0)
    {
      return;
    }
    try
    {
      setValue.accept(certificateForm.getCertificateFile().getBytes());
    }
    catch (Exception e)
    {
      // do not remove this logging! these methods are invoked by thymeleaf. If an exception occurs it is only
      // logged on debug level...
      log.error(e.getMessage(), e);
      throw new CertificateException("could not read certificate with name: " + certificateForm.getName(), e);
    }
  }

  /**
   * a funtional template for setting keystore entries into different fields
   *
   * @param keystoreForm the keystore declaration of which the entries should be set
   * @param setPrivateKey set the private key of the keystore
   * @param setCertificate set the certificate of the keystore
   */
  public static void addKeystoreEntriesToFields(KeystoreForm keystoreForm,
                                                Consumer<byte[]> setPrivateKey,
                                                Consumer<byte[]> setCertificate)
  {
    if (keystoreForm == null || keystoreForm.getKeystoreFile() == null
        || keystoreForm.getKeystoreFile().getSize() == 0)
    {
      return;
    }
    try
    {
      setCertificate.accept(keystoreForm.getX509Certificate().getEncoded());
    }
    catch (CertificateException ex)
    {
      // do not remove this logging! these methods are invoked by thymeleaf. If an exception occurs it is only
      // logged on debug level...
      log.error(ex.getMessage(), ex);
      throw ex;
    }
    catch (Exception e)
    {
      // do not remove this logging! these methods are invoked by thymeleaf. If an exception occurs it is only
      // logged on debug level...
      log.error(e.getMessage(), e);
      throw new CertificateException("could not read certificate with name: " + keystoreForm.getName(), e);
    }

    try
    {
      setPrivateKey.accept(keystoreForm.getPrivateKey().getEncoded());
    }
    catch (KeystoreException ex)
    {
      // do not remove this logging! these methods are invoked by thymeleaf. If an exception occurs it is only
      // logged on debug level...
      log.error(ex.getMessage(), ex);
      throw ex;
    }
    catch (Exception e)
    {
      // do not remove this logging! these methods are invoked by thymeleaf. If an exception occurs it is only
      // logged on debug level...
      log.error(e.getMessage(), e);
      throw new KeystoreException("could not read private key entry from keystore with name: "
                                  + keystoreForm.getName(), e);
    }
  }
}
