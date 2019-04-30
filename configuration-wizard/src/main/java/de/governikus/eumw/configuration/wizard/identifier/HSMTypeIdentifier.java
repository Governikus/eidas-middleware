/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package de.governikus.eumw.configuration.wizard.identifier;

import java.util.Arrays;


/**
 * Encryption Methods used to display possible hsm.type values at the application.properties file
 * configuration
 *
 * @author Ciwinski
 */
public enum HSMTypeIdentifier
{
  NO_HSM, PKCS11;

  /**
   * Used to define if a Encryption method uses a HSM, some fields are hidden when true!
   *
   * @param id EncryptionIdentifier to check
   * @return if tha EncryptionIdentifier uses a HSM
   */
  public static boolean isUsingHSM(HSMTypeIdentifier id)
  {
    switch (id)
    {
      case NO_HSM:
        return false;
      case PKCS11:
        return true;
      default:
        return false;
    }
  }

  /**
   * Used to define if a Encryption method uses a HSM, some fields are hidden when true!
   *
   * @param id EncryptionIdentifier to check
   * @return if tha EncryptionIdentifier uses a HSM
   */
  public static boolean isUsingHSM(String id)
  {
    if (Arrays.stream(HSMTypeIdentifier.values())
              .filter(v -> v.toString().equalsIgnoreCase(id))
              .findAny()
              .isPresent())
    {
      return isUsingHSM(HSMTypeIdentifier.valueOf(id));
    }
    else
    {
      throw new IllegalArgumentException("The String does not Match any EncryptionIdentifier");
    }
  }
}
