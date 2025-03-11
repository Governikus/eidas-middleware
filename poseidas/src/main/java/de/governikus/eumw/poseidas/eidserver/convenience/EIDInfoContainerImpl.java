/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.util.EnumMap;
import java.util.Map;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer;

import oasis.names.tc.dss._1_0.core.schema.ObjectFactory;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * EIDInfoContainerImpl implements the return value of the EIDsequence.
 *
 * @author Alexander Funk
 */
public class EIDInfoContainerImpl implements EIDInfoContainer
{

  private final Map<EIDKeys, EIDInfoResult> infoContainer = new EnumMap<>(EIDKeys.class);

  private static final ObjectFactory FACTORY = new ObjectFactory();

  private Result result;

  // Set to failed on default to only indicate success explicitly
  private EIDStatus status = EIDStatus.FAILED;

  public EIDInfoContainerImpl()
  {
    super();
  }

  @Override
  public Map<EIDKeys, EIDInfoResult> getInfoMap()
  {
    return infoContainer;
  }

  @Override
  public Result getResult()
  {
    if (hasErrors())
    {
      return result;
    }
    return null;
  }

  @Override
  public boolean hasErrors()
  {
    return result != null && !ResultMajor.OK.toString().equals(result.getResultMajor());
  }

  public void setResult(Result inResult)
  {
    result = inResult;
  }

  public void setResult(ResultMajor resultMajor, ResultMinor resultMinor, String resultMessage)
  {
    result = FACTORY.createResult();
    result.setResultMajor(resultMajor.toString());
    result.setResultMinor(resultMinor.toString());
    result.setResultMessage(ECardCoreUtil.generateInternationalStringType(resultMessage));
  }

  public void setStatus(EIDStatus status)
  {
    this.status = status;
  }

  @Override
  public EIDStatus getStatus()
  {
    return status;
  }

}
