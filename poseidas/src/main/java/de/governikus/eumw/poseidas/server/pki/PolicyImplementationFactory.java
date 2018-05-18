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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import de.governikus.eumw.poseidas.server.common.BerCaPolicyConstants;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.ServiceWrapperFactory;


/**
 * Holds the different kinds of process variations used to get CVC and related data
 * 
 * @author tautenhahn
 */
public class PolicyImplementationFactory
{

  private static PolicyImplementationFactory instance = new PolicyImplementationFactory();

  private final Map<String, BerCaPolicy> implementedPolicies = new HashMap<>();

  private PolicyImplementationFactory()
  {
    BerCaPolicy budru = new BasicBerCaPolicy(1, BerCaPolicyConstants.POLICY_DTRUST,
                                             ServiceWrapperFactory.WSDL_VERSION_1_1,
                                             ServiceWrapperFactory.WSDL_VERSION_1_0,
                                             ServiceWrapperFactory.WSDL_VERSION_1_0, false, true, false, true,
                                             true, false);
    implementedPolicies.put(budru.getPolicyId(), budru);
    BerCaPolicy gov = new BasicBerCaPolicy(1, BerCaPolicyConstants.POLICY_GOV,
                                           ServiceWrapperFactory.WSDL_VERSION_1_1,
                                           ServiceWrapperFactory.WSDL_VERSION_1_1,
                                           ServiceWrapperFactory.WSDL_VERSION_1_1, false, true, false, true,
                                           true, false);
    implementedPolicies.put(gov.getPolicyId(), gov);
  }

  /**
   * Singleton getter - clustering no problem
   */
  static PolicyImplementationFactory getInstance()
  {
    return instance;
  }

  /**
   * Return set of supported IDs
   */
  public Set<String> getIds()
  {
    return implementedPolicies.keySet();
  }

  /**
   * Return policy by ID
   * 
   * @param id must match one of the values returned by {@link #getIds()}
   */
  BerCaPolicy getPolicy(String id)
  {
    String effectiveId = id;
    if (!implementedPolicies.containsKey(effectiveId))
    {
      effectiveId = BerCaPolicyConstants.POLICY_SIGNTRUST_A;
    }
    return implementedPolicies.get(effectiveId);
  }

  private static final class BasicBerCaPolicy implements BerCaPolicy
  {

    private final int defaultInitialSequenceNumber;

    private final String id;

    private final boolean initialRequestAsynchron, initialSequenceNumberChoosable,
      refreshOutdatedCVCsAsynchronously, certDescriptionFetch, passiveAuthService, authorizationService;

    private final String wsdlVersionPA;

    private final String wsdlVersionTA;

    private final String wsdlVersionRI;

    @Override
    public int getDefaultInitialSequenceNumber()
    {
      return defaultInitialSequenceNumber;
    }

    @Override
    public String getPolicyId()
    {
      return id;
    }

    BasicBerCaPolicy(int defaultInitialSequenceNumber,
                     String id,
                     String wsdlVersionPA,
                     String wsdlVersionTA,
                     String wsdlVersionRI,
                     boolean initialRequestAsynchron,
                     boolean initialSequenceNumberChoosable,
                     boolean refreshOutdatedCVCsAsynchronously,
                     boolean certDescriptionFetch,
                     boolean passiveAuthService,
                     boolean authorizationService)
    {
      super();
      this.defaultInitialSequenceNumber = defaultInitialSequenceNumber;
      this.id = id;
      this.wsdlVersionPA = wsdlVersionPA;
      this.wsdlVersionTA = wsdlVersionTA;
      this.wsdlVersionRI = wsdlVersionRI;
      this.initialRequestAsynchron = initialRequestAsynchron;
      this.initialSequenceNumberChoosable = initialSequenceNumberChoosable;
      this.refreshOutdatedCVCsAsynchronously = refreshOutdatedCVCsAsynchronously;
      this.certDescriptionFetch = certDescriptionFetch;
      this.passiveAuthService = passiveAuthService;
      this.authorizationService = authorizationService;
    }

    @Override
    public boolean isInitialRequestAsynchron()
    {
      return initialRequestAsynchron;
    }

    @Override
    public boolean isInitialSequenceNumberChoosable()
    {
      return initialSequenceNumberChoosable;
    }

    @Override
    public boolean isRefreshOutdatedCVCsAsynchronously()
    {
      return refreshOutdatedCVCsAsynchronously;
    }

    @Override
    public boolean isRequestWithDescriptionHash()
    {
      return false;
    }

    @Override
    public String getWsdlVersionPassiveAuth()
    {
      return wsdlVersionPA;
    }

    @Override
    public String getWsdlVersionTerminalAuth()
    {
      return wsdlVersionTA;
    }

    @Override
    public String getWsdlVersionRestrictedID()
    {
      return wsdlVersionRI;
    }

    @Override
    public boolean isCertDescriptionFetch()
    {
      return certDescriptionFetch;
    }

    @Override
    public boolean hasPassiveAuthService()
    {
      return passiveAuthService;
    }

    @Override
    public boolean hasAuthorizationService()
    {
      return authorizationService;
    }
  }
}
