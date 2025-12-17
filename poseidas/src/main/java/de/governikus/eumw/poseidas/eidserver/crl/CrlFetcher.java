/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.security.cert.X509CRL;

import de.governikus.eumw.poseidas.eidserver.crl.exception.CertificateValidationException;


/**
 * The CrlFetcher interface provides one methods get a CRL.
 */
public interface CrlFetcher
{

  /**
   * Returns a CRL for the specified url.
   *
   * @param url url of the CRL
   * @return the {@link X509CRL} of the specified url
   * @throws CertificateValidationException if the crl for the url can not be retrieved
   */
  X509CRL get(String url) throws CertificateValidationException;
}
