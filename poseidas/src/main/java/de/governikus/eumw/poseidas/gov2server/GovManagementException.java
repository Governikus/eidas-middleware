/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server;

import de.governikus.eumw.poseidas.gov2server.constants.admin.Code0;
import de.governikus.eumw.poseidas.gov2server.constants.admin.Code1;
import de.governikus.eumw.poseidas.gov2server.constants.admin.Code2;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;


/**
 * Exception carrying a message which is to be displayed on the management console.
 *
 * @author tautenhahn
 */
public class GovManagementException extends Exception
{

  private static final long serialVersionUID = 7777777L;

  private final ManagementMessage message;

  /**
   * Must specify the wrapped message to create such an Exception.
   *
   * @param msg
   */
  public GovManagementException(ManagementMessage msg)
  {
    super(msg.toString());
    this.message = msg;
  }

  /**
   * Convenience constructor, creates message implicitly
   */
  public GovManagementException(Code0 code)
  {
    this(code.createMessage());
  }

  /**
   * Convenience constructor, creates message implicitly
   */
  public GovManagementException(Code1 code, String detail)
  {
    this(code.createMessage(detail));
  }

  /**
   * Convenience constructor, creates message implicitly
   */
  public GovManagementException(Code2 code, String det1, String det2)
  {
    this(code.createMessage(det1, det2));
  }

  /**
   * Return the wrapped message.
   */
  public ManagementMessage getManagementMessage()
  {
    return message;
  }
}
