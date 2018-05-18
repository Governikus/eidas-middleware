/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.core;

import java.util.logging.Logger;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCommonErrorCodes;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * StandardECardExceptionMapper offers an default implementation for the EcardErrorMapper that implements most
 * functions. Any Ecard function will extend this ErrorMapper and provide its own List of Errors as an
 * Extension of ECardErrorCode.
 * 
 * @author Alexander Funk
 */
public abstract class StandardECardExceptionMapper implements ECardErrorMapper
{

  private static final Logger LOGGER = Logger.getLogger(StandardECardExceptionMapper.class.getName());

  @Override
  public final Result toResult(ECardErrorCode e)
  {
    LOGGER.finest("Mapping Errorcode : " + e);
    Result result = new Result();
    result.setResultMajor(ResultMajor.ERROR.toString());
    ResultMinor rm = e.getResultMinor();
    result.setResultMinor(rm != null ? rm.toString() : ResultMinor.COMMON_INTERNAL_ERROR.toString());
    result.setResultMessage(ECardCoreUtil.generateInternationalStringType(e.getMessageKey()));
    return result;
  }

  @Override
  public Object[] getErrorParams(Throwable t)
  {
    return null;
  }

  @Override
  public ECardErrorCode toErrorCode(Throwable t)
  {
    return ECardCommonErrorCodes.UNKNOWN_ERROR;
  }

  @Override
  public final ECardErrorCode toErrorCode(int code)
  {
    ECardErrorCode[] codes = getCodes();
    for ( ECardErrorCode eCardErrorCode : codes )
    {
      if (code == eCardErrorCode.getMessageCode())
      {
        return eCardErrorCode;
      }
    }
    return null;
  }

  @Override
  public final ECardErrorCode toErrorCode(String message)
  {
    if (message == null)
    {
      return null;
    }
    ECardErrorCode[] codes = getCodes();
    for ( ECardErrorCode eCardErrorCode : codes )
    {
      if (message.equals(eCardErrorCode.getMessageKey()))
      {
        return eCardErrorCode;
      }
    }
    return null;
  }

}
