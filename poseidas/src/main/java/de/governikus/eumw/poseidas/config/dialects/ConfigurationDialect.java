package de.governikus.eumw.poseidas.config.dialects;

import java.util.List;
import java.util.Set;

import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.thymeleaf.context.IExpressionContext;
import org.thymeleaf.dialect.IExpressionObjectDialect;
import org.thymeleaf.expression.IExpressionObjectFactory;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.KeyChecker;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Creates a dialect to use all configured certificates and keypairs in thymeleaf via #{...}
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class ConfigurationDialect implements IExpressionObjectDialect
{

  private final ConfigurationService configurationService;

  private final BuildProperties buildProperties;

  private final KeyChecker keyChecker;

  @Override
  public IExpressionObjectFactory getExpressionObjectFactory()
  {
    return new IExpressionObjectFactory()
    {

      @Override
      public Set<String> getAllExpressionObjectNames()
      {
        return Set.of("certificates", "keypairs", "serviceProvider", "projectversion", "KeyChecker");
      }

      @Override
      public Object buildObject(IExpressionContext context, String expressionObjectName)
      {
        return switch (expressionObjectName)
        {
          case "certificates" -> configurationService.getCertificateTypes();
          case "keypairs" -> configurationService.getKeyPairTypes();
          case "serviceProvider" -> configurationService.getConfiguration()
                                                        .map(EidasMiddlewareConfig::getEidConfiguration)
                                                        .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                        .orElse(List.of());
          case "projectversion" -> buildProperties.getVersion();
          case "KeyChecker" -> keyChecker;
          default -> null;
        };
      }

      @Override
      public boolean isCacheable(String expressionObjectName)
      {
        return false;
      }
    };
  }

  @Override
  public String getName()
  {
    return "KeyData";
  }
}
