/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import static org.junit.Assert.assertTrue;

import java.util.Calendar;

import org.junit.Before;
import org.junit.Test;

import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;




public class NPADateParseTest
{

  @Before
  public void setUp() throws Exception
  {}

  @Test
  public void test()
  {
    String dateString = "201510XX";

    String year = dateString.substring(0, 4);
    String month = "XX";
    String day = "XX";
    month = dateString.substring(4, 6);
    day = dateString.substring(6, 8);
    if ("XX".equals(month))
    {
      month = "12";
    }

    DateOfBirthAttribute d;
    if ("XX".equals(day))
    {
      Calendar cal = Calendar.getInstance();
      cal.set(Calendar.MONTH, Integer.parseInt(month) - 1); // because it starts with 0 (januar)
      cal.set(Calendar.YEAR, Integer.parseInt(year));
      cal.set(Calendar.DAY_OF_MONTH, 1);// This is necessary to get proper results
      cal.set(Calendar.DATE, cal.getActualMaximum(Calendar.DATE));
      d = new DateOfBirthAttribute(cal.getTime());
    }
    else
    {
      d = new DateOfBirthAttribute(year + "-" + month + "-" + day);
    }
    assertTrue(d.getDate().equals("2015-10-31"));
  }
}
