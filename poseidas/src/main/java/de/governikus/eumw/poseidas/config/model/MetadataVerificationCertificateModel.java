/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model;

import javax.validation.constraints.NotEmpty;

import de.governikus.eumw.poseidas.config.validation.CertificateNameExists;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration for the metadata signature verification certificate
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class MetadataVerificationCertificateModel
{

  @CertificateNameExists
  @NotEmpty(message = "Has to be selected")
  private String metadataSignatureVerificationCertificateName;

}
