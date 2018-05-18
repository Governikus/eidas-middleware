/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server.constants.admin;

import java.io.Serializable;


/**
 * Base class for a management error code.
 */
public class ManagementCode implements Serializable
{

  private static final long serialVersionUID = 7625568545610397027L;

  private final String code;

  /**
   * Creates a new ManagementCode object.
   * 
   * @param code one of the parameter values specified by the respective ManagmenentMessage class.
   */
  protected ManagementCode(String code)
  {
    this.code = code;
  }

  /**
   * Return the code string.
   */
  public String getCode()
  {
    return code;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int hashCode()
  {
    return ((code == null) ? 0 : code.hashCode());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }

    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }

    final ManagementCode other = (ManagementCode)obj;

    return code == null ? (other.code == null) : code.equals(other.code);
  }

  /**
   * mask all the pipe symbols so that the number of details is retained
   * 
   * @param input
   * @return same as input but with masked "\" and "|"
   */
  protected String mask(String input)
  {
    return input == null ? null : input.replace("\\", "\\\\").replace("|", "\\|");
  }
}
