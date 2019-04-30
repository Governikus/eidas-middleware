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

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 09.02.2018 - 14:22 <br>
 * <br>
 * represents the policy implementation value of the poseidas core configuration
 */
@Slf4j
public enum PolicyImplementationId
{
  GOV_DVCA("govDvca"), BUDRU("budru");

  /**
   * the actual value how it must be filled within the poseidas.xml file
   */
  @Getter
  private String value;

  PolicyImplementationId(String value)
  {
    this.value = value;
  }

  /**
   * tries to resolve the policy implementation id by the value it holds
   *
   * @param value the value of the policy implementation id
   * @return the policy implementation id if found
   */
  public static Optional<PolicyImplementationId> fromValue(String value)
  {
    for ( PolicyImplementationId policyImplementationId : values() )
    {
      if (StringUtils.equals(policyImplementationId.getValue(), value)
          || StringUtils.equals(policyImplementationId.name(), value))
      {
        return Optional.of(policyImplementationId);
      }
    }
    log.warn("could not parse policy implementation id '{}': No enum constant found with this value", value);
    return Optional.empty();
  }
}
