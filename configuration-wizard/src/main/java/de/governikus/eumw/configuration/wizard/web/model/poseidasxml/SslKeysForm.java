/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model.poseidasxml;

import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;
import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;
import de.governikus.eumw.configuration.wizard.web.model.SettingsHelper;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 09.02.2018 - 13:56 <br>
 * <br>
 * this class represents a {@link SslKeysType} for
 * the html view
 */
@Data
@Builder
@AllArgsConstructor
public class SslKeysForm
{

  /**
   * the keystore file that was uploaded
   */
  private CertificateForm serverCertificate;

  /**
   * represents the client key keystore representation
   */
  private KeystoreForm clientKeyForm;

  /**
   * the SSL keys representation from the poseidas core configuration.
   */
  private SslKeysType sslKeysType;

  /**
   * initializes this instance
   */
  public SslKeysForm()
  {
    this.sslKeysType = new SslKeysType();
  }

  /**
   * @see #serverCertificate
   */
  public void setServerCertificate(CertificateForm serverCertificate)
  {
    this.serverCertificate = serverCertificate;
    SettingsHelper.addCertificateToField(serverCertificate, certBytes -> this.sslKeysType.setServerCertificate(certBytes));
  }

  /**
   * @see #clientKeyForm
   */
  public void setClientKeyForm(KeystoreForm clientKeyForm)
  {
    this.clientKeyForm = clientKeyForm;
    SettingsHelper.addKeystoreEntriesToFields(clientKeyForm,
                               privateKeyBytes -> this.sslKeysType.setClientKey(privateKeyBytes),
                               certificateBytes -> this.sslKeysType.setServerCertificate(certificateBytes));
  }

}
