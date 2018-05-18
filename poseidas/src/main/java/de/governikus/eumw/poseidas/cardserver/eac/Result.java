/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac;


/**
 * Interface for any output result of any function, protocol, etc..
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public interface Result<T extends Object>
{

  /**
   * Indicates error.
   * 
   * @return <code>true</code>, when throwable not <code>null</code>, <code>false</code> for no error
   */
  public boolean hasFailed();

  /**
   * Indicates successful execution.
   * 
   * @return <code>true</code> for no error, <code>false</code> - throwable not <code>null</code>,
   */
  public boolean wasSuccessful();

  /**
   * Gets throwable occured.
   * 
   * @return throwable, <code>null</code> for successful execution
   */
  public Throwable getThrowable();

  /**
   * Gets data.
   * 
   * @return data, maybe <code>null</code>
   */
  public T getData();

}
