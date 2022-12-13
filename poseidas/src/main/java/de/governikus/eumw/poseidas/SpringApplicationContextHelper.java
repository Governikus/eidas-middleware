package de.governikus.eumw.poseidas;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;

@Component
public class SpringApplicationContextHelper implements ApplicationContextAware
{

    private static ApplicationContext applicationContext;

    /**
     * Returns the Spring managed bean instance of the {@link ConfigurationService} if it exists. Returns null
     * otherwise.
     *
     * @return the configuration service to load the eumw config from the database
     */
    public static ConfigurationService getConfigurationService()
    {
      return applicationContext.getBean(ConfigurationService.class);
    }


    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException
    {
      SpringApplicationContextHelper.applicationContext = applicationContext;
    }
}
