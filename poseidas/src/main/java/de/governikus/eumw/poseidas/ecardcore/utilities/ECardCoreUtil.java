/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.utilities;

import jakarta.xml.bind.JAXBElement;

import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.ObjectFactory;


public final class ECardCoreUtil
{

  public static InternationalStringType generateInternationalStringType(String value)
  {
    InternationalStringType ist = new ObjectFactory().createInternationalStringType();
    ist.setLang("en");
    ist.setValue(value);
    return ist;
  }

  public static boolean isStartPAOSResponse(Object obj)
  {
    return obj instanceof JAXBElement<?>
           && "StartPAOSResponse".equals(((JAXBElement<?>)obj).getName().getLocalPart());
  }

  private ECardCoreUtil()
  {}
}
