/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model.poseidasxml;

import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import lombok.Data;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 09.02.2018 - 13:46 <br>
 * <br>
 * represents the service provider form object that will be displayed bound to the html view
 */
@Data
public class ServiceProviderForm
{

  /**
   * a unique identifier for this service provider that must later match a configuration field inside the
   * eidasmiddleware.properties file (ENTITYID_INT)
   */
  private String entityID;

  /**
   * the certificate file to check signatures of the received blacklist data
   */
  private CertificateForm blackListTrustAnchor;

  /**
   * the certificate file to check signatures of the received master-list data
   */
  private CertificateForm masterListTrustAnchor;

  /**
   * the certificate file to check signatures of the received defect-list data
   */
  private CertificateForm defectListTrustAnchor;

  /**
   * Defines the policy implementation ID for the connection to the DVCA
   */
  private PolicyImplementationId policyID;

  /**
   * this keys form is a temporary value that is used to bind a {@link SslKeysForm} over this service provider
   * to the html view.
   */
  private SslKeysForm sslKeysForm = new SslKeysForm();

  /**
   * represents a service provider configuration of the poseidas core config
   */
  private ServiceProviderType serviceProvider = new ServiceProviderType();

  /**
   * Defines if this service provider must be used for requests from public service providers
   */
  private boolean publicServiceProvider;

  /**
   * sets the entity ID in the service provider
   */
  public void setEntityID(String entityID)
  {
    this.entityID = entityID;
    this.serviceProvider.setEntityID(entityID);
  }
}
