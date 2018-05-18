/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.eid;

import java.security.cert.X509Certificate;


public class RequestingServiceProvider
{

  private String entityID = null;

  private String assertionConsumerURL = null;

  private X509Certificate signatureCert = null;

  private X509Certificate encryptionCert = null;

  public RequestingServiceProvider(String entityID)
  {
    this.entityID = entityID;
  }

  public void setSignatureCert(X509Certificate signatureCert)
  {
    this.signatureCert = signatureCert;
  }

  public void setEncryptionCert(X509Certificate encryptionCert)
  {
    this.encryptionCert = encryptionCert;
  }

  public void setAssertionConsumerURL(String location)
  {
    this.assertionConsumerURL = location;
  }

  public String getEntityID()
  {
    return entityID;
  }

  public String getAssertionConsumerURL()
  {
    return assertionConsumerURL;
  }

  public X509Certificate getSignatureCert()
  {
    return signatureCert;
  }

  public X509Certificate getEncryptionCert()
  {
    return encryptionCert;
  }
}
