/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.handler;

import java.util.ArrayList;
import java.util.List;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:06 <br>
 * <br>
 * a view object handler is used as storage for a specific type in the view. Since we do not use a database in
 * this configuration wizard we need to keep the data stored in memory
 */
public abstract class ViewObjectHandler<T extends NamedObject>
{

  /**
   * an internal memory containing the named objects
   */
  private final List<T> namedObjects = new ArrayList<>();

  /**
   * add an element to this object handler
   * 
   * @param object the object to be added
   */
  public void add(T object)
  {
    T namedObject = getByName(object.getName());
    if (namedObject != null)
    {
      namedObjects.remove(namedObject);
    }
    namedObjects.add(object);
  }

  /**
   * remove the given object
   * 
   * @param object the object to remove
   */
  public void remove(T object)
  {
    T namedObject = getByName(object.getName());
    if (namedObject != null)
    {
      namedObjects.remove(object);
    }
  }

  /**
   * will remove an object if only the name is present
   * 
   * @param objectName the name of the object to remove
   * @return the named object that has been removed
   */
  public T remove(String objectName)
  {
    T namedObject = getByName(objectName);
    if (namedObject != null)
    {
      namedObjects.remove(namedObject);
      return namedObject;
    }
    return null;
  }

  /**
   * @return all added named objects of this repository
   */
  public List<T> getAll()
  {
    return namedObjects;
  }

  /**
   * will return the named object with the given name
   * 
   * @param name the name to be found
   * @return the named object or null if no entry with this name has been found
   */
  public T getByName(String name)
  {
    return namedObjects.stream().filter(t -> t.getName().equals(name)).findFirst().orElse(null);
  }

  /**
   * will clear all entries in the named objects list
   */
  public void clear()
  {
    namedObjects.clear();
  }
}
