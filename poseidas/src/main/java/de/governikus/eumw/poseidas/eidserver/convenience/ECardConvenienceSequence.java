/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import iso.std.iso_iec._24727.tech.schema.ResponseType;


/**
 * ECardConvenienceSequence a sequence of API calls to find out some information. This is similar to the
 * IDValidator interface in the eIDServer but does not validate things. Instances of this class must figure
 * out what the next request after a given response is to figure the result out. An implementating class will
 * have to define getters that will deliver the final result as soon as isFinished delivers true
 *
 * @author Alexander Funk
 */
public interface ECardConvenienceSequence
{

  /**
   * @return true if all information is available and no further request needs to be issued
   */
  public boolean isFinished();

  /**
   * gets the next request that follow the response. If response is null the sequence is initialized
   *
   * @param response the last response
   * @return the next request
   */
  public Object getNextRequest(ResponseType response);
}
