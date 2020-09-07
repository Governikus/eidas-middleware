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

import lombok.Data;


/**
 * This class represents the form data that is used to create a new service provider in the config wizard
 */
@Data
public class MinimalServiceProviderForm
{

  /**
   * a unique identifier for this service provider
   */
  private String entityID;

  /**
   * this key form is a temporary value that is used to bind a {@link SslKeysForm} over this service provider
   * to the html view.
   */
  private SslKeysForm sslKeysForm = new SslKeysForm();

  /**
   * If set to true this service provider will be used for default requests from public service providers
   */
  private boolean publicServiceProvider;
}
