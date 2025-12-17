/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.core;

import java.util.logging.Level;
import java.util.logging.Logger;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCommonErrorCodes;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * ECardException is the java equivalent of a negative Result in the eCard-Webservice. It can be used to terminate the
 * control-flow in a request implementation, and be converted into an result in the top level request function.
 * <p>
 * Any Exception must at least contain a minor code from the eCard-API. It can to be translated into a result object to
 * create a negative response in an API call. Results shall not be created in the application code manually. They can be
 * either created from an ECardException or from an ECardErrorCode by using the ECardExceptionMapper.
 * </p>
 *
 * @author Alexander Funk
 * @author Thomas Chojecki
 */
@SuppressWarnings("serial")
public class ECardException extends Exception
{

  private static final Logger LOGGER = Logger.getLogger(ECardException.class.getName());

  private final ResultMinor minorCode;

  private final String eCardMessage;

  private final ECardErrorCode errorCode;

  /**
   * the core module may use this field to get the root errorMapper
   */
  private static final ECardErrorMapper errorMapper = new StandardECardExceptionMapper()
  {

    // This should normally have no effect, because the errorMapper is always set during setup of the
    // ecard-API
    // But for safety we set the standard mapper.
    @Override
    public ECardErrorCode[] getCodes()
    {
      return ECardCommonErrorCodes.values();
    }
  };

  /**
   * recreate an ECardException from an Result, useful for checkResult function.
   *
   * @param result
   */
  public ECardException(Result result)
  {
    minorCode = result.getResultMinor() == null ? null : ResultMinor.valueOfEnum(result.getResultMinor());
    eCardMessage = result.getResultMessage() == null || result.getResultMessage().getValue() == null ? null
      : result.getResultMessage().getValue();
    errorCode = errorMapper.toErrorCode(eCardMessage);
  }

  /**
   * Create a new Exception with a ResultMajor.ERROR and the given ResultMinor code.
   *
   * @param minorCode the ResultMinor that should be use.
   * @param message a custom message that will describe the problem.
   */
  public ECardException(ResultMinor minorCode, String message)
  {
    super();
    if (minorCode == null)
    {
      throw new IllegalArgumentException("implementation error: minorCode may not be null");
    }
    this.minorCode = minorCode;
    eCardMessage = message;
    errorCode = ECardCommonErrorCodes.UNKNOWN_ERROR;
  }


  /**
   * Create a new Exception with a ResultMajor.ERROR and the given ResultMinor code.
   *
   * @param minorCode the ResultMinor that should be use.
   * @param cause the throwable that lead to the problem.
   */
  public ECardException(ResultMinor minorCode, Throwable cause)
  {
    super(cause);
    if (minorCode == null)
    {
      throw new IllegalArgumentException("implementation error: minorCode may not be null");
    }
    this.minorCode = minorCode;
    errorCode = errorMapper.toErrorCode(cause);
    eCardMessage = cause.getMessage();
  }

  /**
   * Create a new Exception with a ResultMajor.ERROR and the given ResultMinor code.
   *
   * @param minorCode the ResultMinor that should be use.
   * @param message a custom message that will describe the problem.
   * @param cause the throwable that lead to the problem.
   */
  public ECardException(ResultMinor minorCode, String message, Throwable cause)
  {
    super(cause);
    if (minorCode == null)
    {
      throw new IllegalArgumentException("implementation error: minorCode may not be null");
    }
    this.minorCode = minorCode;
    eCardMessage = message;
    errorCode = errorMapper.toErrorCode(cause);
  }

  /**
   * Return the ResultMinor code associated with the ECardException
   *
   * @return the ResultMinor code associated with the ECardException
   */
  public ResultMinor getMinorCode()
  {
    return minorCode;
  }

  /**
   * An ECardException can be turned into a eCard-API result, with the given minor code and the message. Use this when
   * handling an ECardException. The stackTrace is logged here as a info to trace down probable causes.
   *
   * @return the Result associated with the ECardException
   */
  public Result getResult()
  {
    Result lResult = new Result();
    lResult.setResultMajor(ResultMajor.ERROR.toString());
    lResult.setResultMinor(minorCode.toString());
    lResult.setResultMessage(ECardCoreUtil.generateInternationalStringType(eCardMessage != null ? eCardMessage
      : super.getLocalizedMessage()));
    Throwable lCause = getCause();
    if (lCause != null)
    {
      LOGGER.log(Level.FINE, lCause.getLocalizedMessage(), lCause);
    }
    return lResult;
  }

  @Override
  public String getMessage()
  {
    return eCardMessage;
  }

  @Override
  public String toString()
  {
    return minorCode.toString() + " " + getMessage();
  }

  /**
   * return the error code that identifies this exception uniquely
   *
   * @return the error code
   */
  public ECardErrorCode getErrorCode()
  {
    return errorCode;
  }

}
