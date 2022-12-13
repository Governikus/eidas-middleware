/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;


/**
 * A object of this class contains the input for a eID Request like a useID Request. This data is them
 * processed by the {@link EIDInternal} class.
 *
 * @author Hauke Mehrtens
 */
@Getter
@Setter
@RequiredArgsConstructor
public class EIDRequestInput
{

  private String transactionInfo;

  private String requestedCommunityIDPattern;

  private int requestedMinAge;

  private String requestId;

  private String sessionId;

  private final boolean sessionIdMayDiffer;

  private final Set<EIDKeys> requiredFields = new HashSet<>();

  private final Set<EIDKeys> optionalFields = new HashSet<>();

  public void addRequiredFields(EIDKeys key)
  {
    requiredFields.add(key);
  }

  public void addOptionalFields(EIDKeys key)
  {
    optionalFields.add(key);
  }
}
