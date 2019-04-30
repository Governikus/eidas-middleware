/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.core;

import oasis.names.tc.dss._1_0.core.schema.Result;



/**
 * The purpose of this interface and its implementors is to wrap Exceptions from the supporting libraries into
 * a well defined enumarated set of ECardExceptions and error results from the library. ECardErrorMapper is an
 * interface implemented by every ecard module to map Exceptions to Results that are part of the eCard
 * responses. It can also be used to map from an given ErrorCode to an Result object. ResultObjects in the bos
 * eCard-API are uniquely identified by the ECardErrorCode. The Framework orders all error mappers in a
 * composite error mapper and set it into the ECardException the framework.
 *
 * @see ECardException where it is used to wrapp arbitary exceptions in a defined way to an enumerated set of
 *      ECardException
 * @see StandardECardExceptionMapper provides a default implementation of this interface.
 * @author Alexander Funk
 */
public interface ECardErrorMapper
{

  /**
   * Each implementation should map all exceptions possible in the respective function to an unambiguous error
   * code
   *
   * @param t some arbitrary exception
   * @return the ErrorCode for that Exception
   */
  public ECardErrorCode toErrorCode(Throwable t);


  /**
   * This may return a List of optional Parameters that provide extra information for the given Error Code.
   * The semantic of the parameters must be documented in the specific ECardErrorCode.
   */
  public Object[] getErrorParams(Throwable t);

  /**
   * Every Error code should be mappable to an Result object
   *
   * @param code the code
   * @return an Result as Part of an ECardResponse
   */
  public Result toResult(ECardErrorCode code);

  /**
   * map an messageKey back to an ECardErrorCode. Implemented by StandardEcardException
   *
   * @param messageKey the message Key
   * @return the matching ErrorCode
   */
  public ECardErrorCode toErrorCode(String messageKey);

  /**
   * map an integer message code back to an ECardErrorCode. Implemented by StandardEcardException
   *
   * @param code the message code
   * @return the matching ErrorCode
   */
  public ECardErrorCode toErrorCode(int code);

  /**
   * give an array of all codes in the Enumeration for ErrorCode in that module. This will be used by
   * toErrorCode to map from an code back to an ErroCode.
   *
   * @see StandardECardExceptionMapper#toErrorCode(int)
   * @see StandardECardExceptionMapper#toErrorCode(String)
   * @return all Error Codes
   */
  public ECardErrorCode[] getCodes();
}
