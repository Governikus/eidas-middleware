/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.util.Locale;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;


@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.AUSWEISAPP_REDIRECT)
public class AusweisappRedirect
{

  @GetMapping
  public ModelAndView redirect(@RequestHeader("User-Agent") String userAgentHeader,
                               @RequestParam(required = false, name = "lang") String lang)
  {
    String userAgentLowerCase = userAgentHeader.toLowerCase(Locale.ENGLISH);
    if (userAgentLowerCase.contains("android"))
    {
      return new ModelAndView("redirect:https://play.google.com/store/apps/details?id=com.governikus.ausweisapp2");
    }

    if (userAgentLowerCase.contains("iphone") || userAgentLowerCase.contains("ipod")
        || userAgentLowerCase.contains("ipad"))
    {
      return new ModelAndView("redirect:https://apps.apple.com/us/app/ausweisapp2/id948660805?l=de&ls=1");
    }

    StringBuilder stringBuilder = new StringBuilder("https://www.ausweisapp.bund.de/");
    if (!"de".equals(lang))
    {
      stringBuilder.append("en/");
    }
    stringBuilder.append("download/");
    return new ModelAndView("redirect:" + stringBuilder.toString());
  }
}
