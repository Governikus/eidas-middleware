/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.exceptions;

import de.governikus.eumw.configuration.wizard.web.handler.NamedObject;

/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:27 <br>
 * <br>
 * this exception is used if an invalid name is used in conjunction with the type
 * {@link NamedObject}
 */
public class InvalidNameException extends RuntimeException
{

  public InvalidNameException(String name)
  {
    this(name, null);
  }

  public InvalidNameException(String name, Throwable cause)
  {
    super("the name '" + name + "' is already in use!", cause);
  }
}
