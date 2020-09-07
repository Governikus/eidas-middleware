/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.transmitAPDU.TransmitAPDUResult;


/**
 * Interface for evaluators of transmit results to the specified type.
 *
 * @param <T> type of result
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface TransmitResultEvaluator<T extends FunctionResult<?>> extends APDUCountRestricted
{

  /**
   * Utilities for evaluator.
   * <p>
   * Copyright: Copyright (c) 2010
   * </p>
   * <p>
   * Company: bremen online services GmbH und Co. KG
   * </p>
   *
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public static class Util
  {

    /**
     * Constructor.
     */
    private Util()
    {
      super();
    }

    /**
     * Default check for arguments.
     *
     * @param transmitResult transmit result, <code>null</code> not permitted
     * @param responseIndices indices of response APDUs to be used for evaluation, only positive indices up to
     *          index of last available responses valid, count of indices must between minimum and maximum
     *          response count, <code>null</code> or empty array replaced by array containing index 0 only to
     *          use first response only
     * @return adjusted responseIndices, <code>null</code> replaced by array containing default index 0 for
     *         first response
     * @throws IllegalArgumentException when arguments invalid
     */
    public static int[] checkArguments(TransmitAPDUResult transmitResult, int[] responseIndices)
    {
      AssertUtil.notNull(transmitResult, "transmit result");
      if (ArrayUtil.isNullOrEmpty(responseIndices))
      {
        responseIndices = new int[]{0};
      }
      for ( int responseIndex : responseIndices )
      {
        if (responseIndex < 0)
        {
          throw new IllegalArgumentException("invalid index, only positive value permitted");
        }
        if (responseIndex >= transmitResult.getData().getOutputAPDU().size())
        {
          throw new IllegalArgumentException("invalid index, only value less equals "
                                             + transmitResult.getData().getOutputAPDU().size()
                                             + " permitted");
        }
      }
      return responseIndices;
    }
  }

  /**
   * Evaluate result from transmit result.
   *
   * @param <Q> type of result
   * @param resultClass Class of result, <code>null</code> not permitted
   * @param transmitResult transmit result, <code>null</code> not permitted
   * @param responseIndices indices of response APDUs to be used for evaluation, only positive indices up to
   *          index of last available responses valid, count of indices must between minimum and maximum
   *          response count, <code>null</code> or empty array replaced by array containing index 0 only to
   *          use first response only
   * @return result
   * @throws IllegalArgumentException when arguments invalid
   * @throws Exception when evaluation fails
   */
  public T evaluate(TransmitAPDUResult transmitResult, int[] responseIndices) throws Exception;
}
