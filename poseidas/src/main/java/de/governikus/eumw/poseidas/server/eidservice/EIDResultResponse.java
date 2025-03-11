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

import java.util.EnumMap;
import java.util.Map;

import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;

import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * A object of this class contains the response for a eID Result Request like a getResultRequest. This data is
 * provided by the {@link EIDInternal} class an then handled by the SAML validator or the eID-Webservice.
 *
 * @author Hauke Mehrtens
 */
public class EIDResultResponse
{

  private final String resultMajor;

  private final String resultMinor;

  private String resultMessage;

  private final String logPrefix;

  private final Map<EIDKeys, EIDInfoResult> infoMap = new EnumMap<>(EIDKeys.class);

  EIDResultResponse(String resultMajor,
                    String resultMinor,
                    String resultMessage,
                    String logPrefix)
  {
    this.resultMajor = resultMajor;
    this.resultMinor = resultMinor;
    this.resultMessage = resultMessage;
    this.logPrefix = logPrefix;
  }

  EIDResultResponse(Result result, Map<EIDKeys, EIDInfoResult> infoMap, String logPrefix)
  {
    this.resultMajor = result.getResultMajor();
    this.resultMinor = result.getResultMinor();
    if (result.getResultMessage() != null)
    {
      this.resultMessage = result.getResultMessage().getValue();
    }
    if (infoMap != null)
    {
      this.infoMap.putAll(infoMap);
    }
    this.logPrefix = logPrefix;
  }

  public Result getResult()
  {
    Result result = new Result();
    result.setResultMajor(resultMajor);
    result.setResultMinor(resultMinor);
    result.setResultMessage(ECardCoreUtil.generateInternationalStringType(resultMessage));
    return result;
  }

  public String getResultMajor()
  {
    return resultMajor;
  }

  public String getResultMinor()
  {
    return resultMinor;
  }

  public String getResultMessage()
  {
    return resultMessage;
  }

  public void setResultMessage(String resultMessage)
  {
    this.resultMessage = resultMessage;
  }

  public Map<EIDKeys, EIDInfoResult> getInfoMap()
  {
    return infoMap;
  }

  public EIDInfoResult getEIDInfo(EIDKeys key)
  {
    return infoMap.get(key);
  }


  public String getLogPrefix()
  {
    return logPrefix;
  }

}
