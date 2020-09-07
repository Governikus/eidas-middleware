/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidascommon;

/**
 * Exception wrapping an error code with some optional details.
 *
 * @author tt
 */
public class ErrorCodeException extends Exception
{

  private static final long serialVersionUID = 1L;

  private final ErrorCode code;

  private final String[] details;

  /**
   * Create new instance
   *
   * @param code
   * @param detail should match the given error code value
   */
  public ErrorCodeException(ErrorCode code, String... detail)
  {
    this.code = code;
    details = detail;
  }

  /**
   * Convenience constructor.
   *
   * @param code must expect one detail
   * @param t
   */
  public ErrorCodeException(ErrorCode code, Throwable t)
  {
    this.code = code;
    details = new String[]{t.getMessage()};
  }

  @Override
  public String getMessage()
  {
    return code.toDescription(details);
  }

  /**
   * @return code represented by this exception
   */
  public ErrorCode getCode()
  {
    return code;
  }

  /**
   * @return details array
   */
  public String[] getDetails()
  {
    return details;
  }

}
