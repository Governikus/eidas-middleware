/*
 * Copyright (c) 2023 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


/**
 * Redirect users that open the index page <code>/</code> to the actual start page at <code>/NewRequesterServlet</code>
 */
@Controller
@RequestMapping("/")
public class IndexRedirect
{

  /**
   * Redirect users that open the index page <code>/</code> to the actual start page at
   * <code>/NewRequesterServlet</code>
   */
  @GetMapping()
  public String redirectToRequesterServlet()
  {
    return "redirect:/NewRequesterServlet";
  }
}
