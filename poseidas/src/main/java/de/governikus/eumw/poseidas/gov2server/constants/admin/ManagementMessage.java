/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
 * Represents a (usually error-) message which can be displayed on the administration console. Objects of this
 * class consist of a code which must be understood by the administration console and possibly one or more
 * details Strings depending on the respective code.
 *
 * @author tt
 */
public class ManagementMessage implements Serializable
{

  private static final long serialVersionUID = 7964658179143347423L;

  private final String details;

  private final ManagementCode code;

  /**
   * Creates a new ManagementMessage object. This method must remain protected in each implementing class!
   *
   * @param code fixed code value defined by the implementing class
   * @param details further explaining information specified together with the respective message code.
   */
  ManagementMessage(ManagementCode code, String details)
  {
    this.code = code;
    this.details = details;
  }

  /**
   * Return the code of this message.
   */
  public ManagementCode getCode()
  {
    return code;
  }

  /**
   * Return the details of this message.
   */
  public String getDetails() {
    return details;
  }

  /**
   * Return the String representation as given to the WebAdmin
   */
  @Override
  public String toString()
  {
    return (details == null) ? code.getCode() : (code.getCode() + "|" + details);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int hashCode()
  {
    return ((code == null) ? 0 : code.hashCode()) + 37 * ((details == null) ? 0 : details.hashCode());
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
    ManagementMessage other = (ManagementMessage)obj;
    if (code == null)
    {
      if (other.code != null)
      {
        return false;
      }
    }
    else if (!code.equals(other.code))
    {
      return false;
    }
    if (details == null)
    {
      if (other.details != null)
      {
        return false;
      }
    }
    else if (!details.equals(other.details))
    {
      return false;
    }
    return true;
  }


}
