/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

import java.io.IOException;


/**
 * Abstract class for domain parameter infos.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public abstract class DomainParameterInfo extends SecurityInfo
{

  /**
   * Current lowest domain parameter ID.
   */
  public static final int MIN_DOMAIN_PARAMETER_ID = 8;

  /**
   * Current highest domain parameter ID.
   */
  public static final int MAX_DOMAIN_PARAMETER_ID = 18;

  /**
   * Reference to the <code>domainParameter</code> child element.
   */
  protected AlgorithmIdentifier domainParameter = null;

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of domain parameter info
   * @throws IOException if reading bytes fails
   */
  DomainParameterInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>domainParameter</code>.
   *
   * @return {@link AlgorithmIdentifier} instance containing <code>domainParameter</code>, <code>null</code>
   *         possible
   * @throws IOException if error in getting
   */
  public final AlgorithmIdentifier getDomainParameter() throws IOException
  {
    if (this.domainParameter == null)
    {
      this.loadDomainParameter();
    }
    return this.domainParameter;
  }

  @Override
  protected void update()
  {
    this.domainParameter = null;
  }

  protected abstract void loadDomainParameter() throws IOException;

  @Override
  public boolean equals(Object object)
  {
    return super.equals(object);
  }

  @Override
  public int hashCode()
  {
    return super.hashCode();
  }
}
