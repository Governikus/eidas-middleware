package de.governikus.eumw.databasecleanup.hsql.secondary.configuration;

import java.util.HashMap;

import javax.sql.DataSource;

import jakarta.persistence.EntityManagerFactory;

import org.hsqldb.DatabaseURL;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import lombok.extern.slf4j.Slf4j;


/**
 * The database configuration to access the new HSQL database
 */
@Slf4j
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = "de.governikus.eumw.databasecleanup.hsql.secondary.repositories", entityManagerFactoryRef = HsqlSecondaryDatabaseConfig.HSQL_ENTITY_MANAGER_FACTORY, transactionManagerRef = HsqlSecondaryDatabaseConfig.HSQL_TRANSACTION_MANAGER)
public class HsqlSecondaryDatabaseConfig
{

  public static final String HSQL_ENTITY_MANAGER_FACTORY = "secondaryHsqlEntityManagerFactory";

  public static final String HSQL_DATA_SOURCE = "secondaryHsqlDataSource";

  public static final String HSQL_TRANSACTION_MANAGER = "secondaryHsqlTransactionManager";

  public static final String CLEANED_DB_SUFFIX = "-cleaned";

  @Bean(name = HSQL_DATA_SOURCE)
  public DataSource hsqlDataSource(@Value("${spring.datasource.url}") String primaryHsqlDatabaseUrl,
                                   @Value("${spring.datasource.username}") String hsqlDatabaseUsername,
                                   @Value("${spring.datasource.password}") String hsqlDatabasePassword,
                                   @Value("${hsql.datasource.maxcon:2}") int maximumPoolSize)
  {
    String primaryPath = DatabaseURL.parseURL(primaryHsqlDatabaseUrl, true, false)
                                    .getProperty(DatabaseURL.url_database);
    String hsqlDatabaseUrl = primaryHsqlDatabaseUrl.replace(primaryPath, primaryPath + CLEANED_DB_SUFFIX)
                             + ";hsqldb.lob_file_scale=1";

    log.info("connecting to the hsql database at: {}", hsqlDatabaseUrl);

    var dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");
    dataSource.setUrl(hsqlDatabaseUrl);
    dataSource.setUsername(hsqlDatabaseUsername);
    dataSource.setPassword(hsqlDatabasePassword);

    HikariConfig hikariConfig = new HikariConfig();
    hikariConfig.setPoolName("Hsql database connection pool");
    hikariConfig.setDataSource(dataSource);
    hikariConfig.setMaximumPoolSize(maximumPoolSize);
    hikariConfig.setMinimumIdle(1);
    hikariConfig.setConnectionTimeout(3000);


    return new HikariDataSource(hikariConfig);
  }

  @Bean(name = HSQL_ENTITY_MANAGER_FACTORY)
  public EntityManagerFactory hsqlEntityManagerFactory(@Qualifier(HSQL_DATA_SOURCE) DataSource hsqlDataSource)
  {
    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
    em.setDataSource(hsqlDataSource);
    em.setPackagesToScan("de.governikus.eumw.databasecleanup.entities");
    JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
    em.setJpaVendorAdapter(vendorAdapter);

    HashMap<String, Object> properties = new HashMap<>();
    properties.put("hibernate.hbm2ddl.auto", "update");

    em.setJpaPropertyMap(properties);

    em.afterPropertiesSet();
    return em.getObject();
  }

  @Bean(name = HSQL_TRANSACTION_MANAGER)
  public PlatformTransactionManager hsqlTransactionManager(@Qualifier(HSQL_DATA_SOURCE) DataSource hsqlDataSource)
  {
    return new JpaTransactionManager(hsqlEntityManagerFactory(hsqlDataSource));
  }

}
