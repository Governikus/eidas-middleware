/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import lombok.Getter;


/**
 * Configuration for PKCS#11 based HSM.
 *
 * @author ast
 */
@Getter
public class PKCS11HSMConfiguration implements HSMConfiguration
{

  /**
   * Path to PKCS#11 config file.
   */
  private String configFileName;

  /**
   * Password for the user account on PKCS#11 HSM.
   */
  private String password;

  /**
   * Constructor.
   *
   * @param configName path to PKCS#11 config file
   * @param password password for the user account on PKCS#11 HSM
   */
  public PKCS11HSMConfiguration(String configName, String password)
  {
    AssertUtil.notNull(configName, "config file name");
    AssertUtil.notNull(password, "password");
    this.configFileName = configName;
    this.password = password;
  }
}
