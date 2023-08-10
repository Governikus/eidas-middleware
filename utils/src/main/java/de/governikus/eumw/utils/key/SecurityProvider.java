/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.utils.key;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import lombok.experimental.UtilityClass;


/**
 * this class will provide some security providers
 */
@UtilityClass
public final class SecurityProvider
{

  /**
   * The BouncyCastle provider that is needed for PKCS12 keystores.
   */
  public static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  /**
   * The BouncyCastle JSSE provider that is needed for Brainpool support.
   */
  public static final Provider BOUNCY_CASTLE_JSSE_PROVIDER = new BouncyCastleJsseProvider();

  /**
   * The Sun JSSE provider that is needed for TLS client keys in HSM.
   */
  public static final Provider SUN_JSSE_PROVIDER = Security.getProvider("SunJSSE");
}
