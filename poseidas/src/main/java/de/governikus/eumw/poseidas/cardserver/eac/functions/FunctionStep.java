/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions;

import iso.std.iso_iec._24727.tech.schema.Transmit;
import iso.std.iso_iec._24727.tech.schema.TransmitResponse;


/**
 * Interface for step implementations of functions.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface FunctionStep<S extends FunctionParameter, T extends FunctionResult<?>>
{

  /**
   * @param parameter parameters for creating card commands, required in some functions, not required (
   *          <code>null</code> permitted) in others
   * @param sh {@link SlotHandleType} required for constructing {@link Transmit} instance, remains unchanged by this
   *          method, <code>null</code> not permitted
   * @return {@link Transmit} instance containing card commands and accepted response codes
   * @throws IllegalStateException if called in incorrect order (correct order is: parameterStep - resultStep -
   *           parameterStep - ...)
   * @throws IllegalArgumentException if sht <code>null</code> or if parameter <code>null</code> when required
   * @throws InternalError
   */
  public abstract Transmit parameterStep(S parameter, byte[] sh);

  /**
   * Evaluates responses from card.
   *
   * @param result responses from card as {@link TransmitResponse}, <code>null</code> not permitted
   * @return result of function
   * @throws IllegalStateException if called in incorrect order (correct order is: parameterStep - resultStep -
   *           parameterStep - ...)
   * @throws IllegalArgumentException if result <code>null</code>
   */
  public abstract T resultStep(TransmitResponse result);
}
