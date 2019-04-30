/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.utils.key.exceptions;

/**
 * This Exception will be thrown if the creation of a keystore fails
 */
public class KeyStoreCreationFailedException extends RuntimeException
{

  public KeyStoreCreationFailedException(String message)
  {
    super(message);
  }

  public KeyStoreCreationFailedException(String message, Throwable cause)
  {
    super(message, cause);
  }

  public KeyStoreCreationFailedException(Throwable cause)
  {
    super(cause);
  }
}
