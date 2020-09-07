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

/**
 * Marker interface for anything that contains domain parameter infos. That could be a class containing all
 * the parameters, another alternative is a class containing simply an ID for a set of standard parameters.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface GeneralDomainParameterInfo
{

  /**
   * Current lowest domain parameter ID.
   */
  public static final int MIN_DOMAIN_PARAMETER_ID = 8;

  /**
   * Current highest domain parameter ID.
   */
  public static final int MAX_DOMAIN_PARAMETER_ID = 18;
}
