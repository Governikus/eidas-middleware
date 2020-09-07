/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.exceptions;


/**
 * To be thrown when the POSeIDAS.xml is bad
 */
public class InvalidConfigurationException extends Exception
{

  static final long serialVersionUID = 1L;

  /**
   * Throw this exception if the configuration is not complete and normal operations would be impossible
   *
   * @param message Additional information regarding the bad configuration
   */
  public InvalidConfigurationException(String message)
  {
    super(message);
  }

  /**
   * Throw this exception if the configuration is not complete and normal operations would be impossible.
   *
   * @param message Additional information regarding the bad configuration
   * @param cause Root exception
   */
  public InvalidConfigurationException(String message, Throwable cause)
  {
    super(message, cause);
  }

}
