/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;


public class FindNumber
{

  @Before
  public void setUp() throws Exception
  {}

  @Test
  public void test()
  {
    String s = "Hauptrasse 14";
    int idx = -1;
    for ( int i = 0 ; i < s.length() ; i++ )
    {
      if (Character.isDigit(s.charAt(i)))
      {
        idx = i;
        break;
      }
    }
    String street = s.substring(0, idx).trim();
    String nr = s.substring(idx);
    assertTrue("Hauptrasse".equals(street));
    assertTrue("14".equals(nr));
  }
}
