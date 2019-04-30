/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.handler;

/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 28.03.2018 - 13:28 <br>
 * <br>
 */
public final class HandlerHolder
{

  /**
   * a keystore handler that will hold all loaded keystores for the runtime of this application
   */
  private static final KeystoreHandler KEYSTORE_HANDLER = new KeystoreHandler();

  /**
   * a certficate handler that will hold all loaded certificates for the runtime of this application
   */
  private static final CertificateHandler CERTIFICATE_HANDLER = new CertificateHandler();

  /**
   * utility class constructor
   */
  private HandlerHolder()
  {
    super();
  }

  /**
   * @see #KEYSTORE_HANDLER
   */
  public static KeystoreHandler getKeystoreHandler()
  {
    return KEYSTORE_HANDLER;
  }

  /**
   * @see #CERTIFICATE_HANDLER
   */
  public static CertificateHandler getCertificateHandler()
  {
    return CERTIFICATE_HANDLER;
  }
}
