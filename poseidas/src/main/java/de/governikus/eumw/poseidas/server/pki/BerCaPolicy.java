/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

/**
 * Description of the parts of a BerCA Policy which have to be implemented by poseidas.
 * 
 * @author tautenhahn
 */
public interface BerCaPolicy
{

  /**
   * Return an Id of this policy - unique among the set of implemented policies
   */
  public String getPolicyId();

  /**
   * Return true if poseidas should issue a subsequent request for expired CVCs and expect the CVC to be given
   * in a callback.
   */
  public boolean isRefreshOutdatedCVCsAsynchronously();

  /**
   * return the sequence number expected in an initial CVC request
   */
  public int getDefaultInitialSequenceNumber();

  /**
   * Return true if poseidas shall take the sequence number of an initial request from user input
   */
  public boolean isInitialSequenceNumberChoosable();

  /**
   * return true if initial request is handled asynchronously as TR requires
   */
  public boolean isInitialRequestAsynchron();

  /**
   * Return <code>true</code> for inserting hash of description into request.
   */
  public boolean isRequestWithDescriptionHash();

  /**
   * Return the version of the passive authentication service WSDL used by the BerCA.
   */
  public String getWsdlVersionPassiveAuth();

  /**
   * Return the version of the terminal authentication service WSDL used by the BerCA.
   */
  public String getWsdlVersionTerminalAuth();

  /**
   * Return the version of the restricted identification service WSDL used by the BerCA.
   */
  public String getWsdlVersionRestrictedID();

  /**
   * Returns true if the CA has a service to fetch the certificate description.
   */
  public boolean isCertDescriptionFetch();

  /**
   * Returns true if the CA has an passive authentication service to fetch the master and defect list.
   */
  public boolean hasPassiveAuthService();

  /**
   * Returns true if this BerCa supports an AuthorizationService like the telesec does.
   */
  public boolean hasAuthorizationService();
}
