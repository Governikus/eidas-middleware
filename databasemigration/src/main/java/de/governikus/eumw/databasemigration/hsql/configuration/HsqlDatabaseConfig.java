package de.governikus.eumw.databasemigration.hsql.configuration;

import java.util.HashMap;

import javax.sql.DataSource;

import jakarta.persistence.EntityManagerFactory;

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
@EnableJpaRepositories(basePackages = "de.governikus.eumw.databasemigration.hsql.repositories", entityManagerFactoryRef = "hsqlEntityManagerFactory", transactionManagerRef = "hsqlTransactionManager")
public class HsqlDatabaseConfig
{

  /**
   * the database URL
   */
  private final String hsqlDatabaseUrl;

  /**
   * the database user
   */
  private final String hsqlDatabaseUsername;

  /**
   * the database password
   */
  private final String hsqlDatabasePassword;

  /**
   * The maximum amount of database connections.
   */
  private final int maximumPoolSize;

  public HsqlDatabaseConfig(@Value("${hsql.datasource.url:}") String hsqlDatabaseUrl,
                            @Value("${hsql.datasource.username:}") String hsqlDatabaseUsername,
                            @Value("${hsql.datasource.password:}") String hsqlDatabasePassword,
                            @Value("${hsql.datasource.maxcon:2}") int maximumPoolSize)
  {
    this.hsqlDatabaseUrl = hsqlDatabaseUrl;
    this.hsqlDatabaseUsername = hsqlDatabaseUsername;
    this.hsqlDatabasePassword = hsqlDatabasePassword;
    this.maximumPoolSize = maximumPoolSize;
  }

  @Bean(name = "hsqlDataSource")
  public DataSource hsqlDataSource()
  {
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

  @Bean(name = "hsqlEntityManagerFactory")
  public EntityManagerFactory hsqlEntityManagerFactory(@Qualifier("hsqlDataSource") DataSource hsqlDataSource)
  {
    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
    em.setDataSource(hsqlDataSource);
    em.setPackagesToScan("de.governikus.eumw.databasemigration.entities");
    JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
    em.setJpaVendorAdapter(vendorAdapter);

    HashMap<String, Object> properties = new HashMap<>();
    properties.put("hibernate.hbm2ddl.auto", "update");

    em.setJpaPropertyMap(properties);

    em.afterPropertiesSet();
    return em.getObject();
  }

  @Bean(name = "hsqlTransactionManager")
  public PlatformTransactionManager hsqlTransactionManager(@Qualifier("hsqlDataSource") DataSource hsqlDataSource)
  {
    return new JpaTransactionManager(hsqlEntityManagerFactory(hsqlDataSource));
  }
}
