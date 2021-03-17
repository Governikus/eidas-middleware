/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.identifier;

import lombok.Getter;

/**
 * keys for the application properties
 *
 * @author Prange, Behrends
 */
public enum ApplicationPropertiesIdentifier
{
  SERVER_PORT("server.port"),
  ADMIN_INTERFACE_PORT("server.adminInterfacePort"),
  SERVER_SSL_KEYSTORE("server.ssl.key-store"),
  SERVER_SSL_KEYSTORE_PASSWORD("server.ssl.key-store-password"),
  SERVER_SSL_KEY_PASSWORD("server.ssl.key-password"),
  SERVER_SSL_KEYSTORE_TYPE("server.ssl.keyStoreType"),
  SERVER_SSL_KEY_ALIAS("server.ssl.keyAlias"),
  DATASOURCE_URL("spring.datasource.url"),
  DATASOURCE_USERNAME("spring.datasource.username"),
  DATASOURCE_PASSWORD("spring.datasource.password"),
  ADMIN_USERNAME("poseidas.admin.username"),
  ADMIN_PASSWORD("poseidas.admin.hashed.password"),
  LOGGING_FILE("logging.file.name"),
  HSM_TYPE("hsm.type"),
  HSM_KEYS_DELETE("hsm.keys.delete"),
  HSM_KEYS_ARCHIVE("hsm.keys.archive"),
  PKCS11_SUN_CONFIG_PROVIDER_FILE_PATH("pkcs11.config"),
  PKCS11_HSM_PASSWORD("pkcs11.passwd");


  /**
   * property key
   */
  @Getter
  private String propertyName;

  private ApplicationPropertiesIdentifier(String propertyName)
  {
    this.propertyName = propertyName;
  }
}
