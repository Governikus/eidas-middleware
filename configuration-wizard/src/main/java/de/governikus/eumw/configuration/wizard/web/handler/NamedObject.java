/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.handler;

/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:10 <br>
 * <br>
 * we will use some objects in the view that will be uploaded in advance and that can then be selected by a
 * name. These objects must implement this interface.
 */
public interface NamedObject
{

  /**
   * a unique name that is used to identify the given object.
   *
   * @return the name of the object
   */
  String getName();

  /**
   * checks if this object is a valid objecz
   *
   * @return true if all conditions are met, false else
   */
  boolean isValid();
}
