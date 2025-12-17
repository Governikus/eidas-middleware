/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.core;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;



/**
 * The ECardErrorCode identifies one Error condition of the bos eCardAPI without ambiguity. It therefore allows a more
 * fine grained control and information about error conditions, that the ResultMinor codes given in the eCard
 * specification. That means one ResultMinor code may map to more then one ECardErrorCode. An Error Code always contains
 * an unambiguent String that can be used as a key into an Message resource bundle on client side.
 *
 * @author Alexander Funk
 */
public interface ECardErrorCode
{

  /**
   * a unique String that can be used as a key in message catalogs. This shall have the ecard module package as its
   * prefix.
   *
   * @return the string that can be used as index into the properties table
   */
  public String getMessageKey();

  /**
   * a unique integer that can be used as an easy reference to the documentation.
   *
   * @return the message code
   */
  public int getMessageCode();

  /**
   * if null is returned, the implementation may return a common error
   *
   * @return a specific minor code or null
   * @see ResultMinor#COMMON_INTERNAL_ERROR
   */
  public ResultMinor getResultMinor();
}
