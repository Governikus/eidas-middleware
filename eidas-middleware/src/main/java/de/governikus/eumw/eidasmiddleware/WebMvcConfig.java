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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

import de.governikus.eumw.eidascommon.ContextPaths;


/**
 * Configuration that allows to access static resources from two locations
 */
@Configuration("EidasMiddlewareWebMvcConfig")
public class WebMvcConfig implements WebMvcConfigurer
{

  public static final String WILDCARD_PATTERN = "/**";

  @Value("${spring.resources.static-locations}")
  private String staticResourceLocations;

  /**
   * Adds the root and the eidas-middleware path to the accessible path for static resources.
   *
   * @param registry
   */
  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry)
  {
    String[] resourceLocations = staticResourceLocations.split(",");

    if (!registry.hasMappingForPattern(ContextPaths.EIDAS_CONTEXT_PATH + WILDCARD_PATTERN))
    {
      registry.addResourceHandler(ContextPaths.EIDAS_CONTEXT_PATH + WILDCARD_PATTERN)
              .addResourceLocations(resourceLocations)
              .resourceChain(true)
              .addResolver(new PathResourceResolver());
    }

    if (!registry.hasMappingForPattern(ContextPaths.EIDAS_CONTEXT_PATH + "/webjars/**"))
    {
      registry.addResourceHandler(ContextPaths.EIDAS_CONTEXT_PATH + "/webjars/**")
              .addResourceLocations("/webjars/");
    }

  }
}
