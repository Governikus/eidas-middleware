/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.springboot;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Value;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 11.06.2017 <br>
 * <br>
 */
@Slf4j
public abstract class SpringBootControllerTest
{

  /**
   * slash constant
   */
  public static final String SLASH = "/";

  /**
   * if spring boot test uses a random port the port will be injected into this variable
   */
  @Getter
  @Value("${local.server.port:8080}")
  private int localServerPort;

  /**
   * contains the URL to which the requests must be sent
   */
  private String defaultUrl;

  /**
   * will initialize the url under which the locally started tomcat can be reached
   */
  @BeforeEach
  public void initializeUrl()
  {
    defaultUrl = "http://localhost:" + localServerPort;
  }

  /**
   * this method will create a request url with the given path
   *
   * @param path the context path to the method that should be used
   * @return the complete server-url with the given context path to the method that should be used
   */
  public String getRequestUrl(String path)
  {
    return defaultUrl + (path.startsWith("/") ? path : "/" + path);
  }
}
