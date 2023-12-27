/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.eid;

import java.security.cert.X509Certificate;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


/**
 * Class to hold data of requesting service providers.
 */
@Getter
@Setter
public class RequestingServiceProvider
{

  private String entityID = null;

  private String assertionConsumerURL = null;

  private X509Certificate signatureCert = null;

  private X509Certificate encryptionCert = null;

  private SPTypeEnumeration sectorType;

  public RequestingServiceProvider(String entityID)
  {
    this.entityID = entityID;
  }
}
