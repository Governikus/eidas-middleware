/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.eid;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import de.governikus.eumw.eidascommon.Utils;


/**
 * Helper class for server side handling of HTTP requests and responses
 * 
 * @author tautenhahn
 */
public final class HttpServerUtils
{

  private HttpServerUtils()
  {
    super();
  }

  /**
   * Set a content holding a forward page into a given HTTP response. Action and style sheet are inserted by
   * this method.
   * 
   * @param content
   * @param url
   * @param cssUrl
   * @param resp
   * @throws IOException
   */
  public static void setPostContent(String content, String url, String cssUrl, HttpServletResponse resp)
    throws IOException
  {
    String html = content.replace("${ACTION}", url);
    html = html.replace("${CSS_URL}",
                        (cssUrl == null || cssUrl.trim().isEmpty()) ? "style.css"
                          : Utils.replaceHTMLSymbols(cssUrl));
    resp.setHeader("Cache-Control", "no-cache, no-store");
    resp.setHeader("Pragma", "no-cache");
    resp.setContentType("text/html");
    resp.setCharacterEncoding(Utils.ENCODING);
    resp.getWriter().write(html);
  }

}
