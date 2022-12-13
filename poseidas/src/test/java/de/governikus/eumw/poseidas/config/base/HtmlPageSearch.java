/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.base;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.function.Predicate;
import java.util.stream.StreamSupport;

import com.gargoylesoftware.htmlunit.html.DomElement;


/**
 * Search for elements in a {@link com.gargoylesoftware.htmlunit.html.HtmlPage}
 *
 * @param <T> Any element of a {@link com.gargoylesoftware.htmlunit.html.HtmlPage}
 */
public class HtmlPageSearch<T extends DomElement>
{

  /**
   * Search for all elements that fit to the given predicate. This search order is not deterministic if there are
   * multiple possible results.
   *
   * @param rootElement the root of the search
   * @param filter the filter predicate to identify the wanted element
   * @param clazz the {@link Class} of the wanted element. Used to identify and cast.
   * @return
   */
  public List<T> searchAllInTree(DomElement rootElement, Predicate<T> filter, Class<T> clazz)
  {
    List<T> found = new LinkedList<>();
    Queue<DomElement> toVisit = new LinkedList<>(List.of(rootElement));

    for ( DomElement toCheck = toVisit.poll() ; !toVisit.isEmpty() ; )
    {
      toVisit.remove(toCheck);

      if (clazz.isInstance(toCheck) && filter.test((T)toCheck))
      {
        found.add((T)toCheck);
      }

      StreamSupport.stream(rootElement.getChildElements().spliterator(), true).forEach(e -> toVisit.add((T)e));
    }
    return found;
  }

  /**
   * Search for an element that fits to the given predicate. This search is not deterministic if there are multiple
   * possible results.
   *
   * @param rootElement the root of the search
   * @param filter the filter predicate to identify the wanted element
   * @param clazz the {@link Class} of the wanted element. Used to identify and cast.
   * @return
   */
  public Optional<T> searchFirstInTree(DomElement rootElement, Predicate<T> filter, Class<T> clazz)
  {

    Queue<DomElement> toVisit = new LinkedList<>(List.of(rootElement));

    while (!toVisit.isEmpty())
    {
      DomElement toCheck = toVisit.poll();
      toVisit.remove(toCheck);

      if (clazz.isInstance(toCheck) && filter.test((T)toCheck))
      {
        return Optional.of((T)toCheck);
      }

      StreamSupport.stream(toCheck.getChildElements().spliterator(), true).forEach(e -> toVisit.add((T)e));
    }
    return Optional.empty();
  }
}
