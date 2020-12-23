/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Constants
{

  public static final String DEFAULT_PROVIDER_NAME = "DefaultProvider";

  static String format(Date date)
  {
    return getSamlDateFormat().format(date);
  }

  public static Date parse(String value) throws ParseException
  {
    return getSamlDateFormat().parse(value);
  }

  private static SimpleDateFormat getSamlDateFormat()
  {
    SimpleDateFormat samlDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    samlDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    return samlDateFormat;
  }
}
