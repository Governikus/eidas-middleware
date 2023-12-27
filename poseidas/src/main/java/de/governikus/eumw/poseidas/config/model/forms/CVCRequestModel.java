/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.model.forms;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.Range;

import lombok.Data;


/**
 * This model represents the form for the initial CVC request
 *
 * @author bpr
 */
@Data
public class CVCRequestModel
{

  @NotBlank(message = "Country code must not be empty")
  @Length(min = 2, max = 2, message = "Country code has to be exactly 2 characters long")
  private String countryCode;

  @NotBlank(message = "CHR Mnemonic must not be empty")
  @Length(max = 9, message = "CHR Mnemonic must not be longer than 9 characters")
  private String chrMnemonic;

  @Range(min = 0, max = 99999, message = "Sequence number must be between 0-99999")
  @NotNull(message = "Sequence number must not be empty")
  private Integer sequenceNumber;

  private String rscChr;

}
