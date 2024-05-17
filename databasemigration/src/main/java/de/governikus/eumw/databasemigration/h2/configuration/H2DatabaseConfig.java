package de.governikus.eumw.databasemigration.h2.configuration;

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
 * The database configuration to access the old H2 database
 */
@Slf4j
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = "de.governikus.eumw.databasemigration.h2.repositories", entityManagerFactoryRef = "h2EntityManagerFactory", transactionManagerRef = "h2TransactionManager")
public class H2DatabaseConfig
{

  /**
   * the database URL
   */
  private final String h2DatabaseUrl;

  /**
   * the database user
   */
  private final String h2DatabaseUsername;

  /**
   * the database password
   */
  private final String h2DatabasePassword;

  /**
   * The maximum amount of database connections.
   */
  private final int maximumPoolSize;

  public H2DatabaseConfig(@Value("${h2.datasource.url:}") String h2DatabaseUrl,
                          @Value("${h2.datasource.username:}") String h2DatabaseUsername,
                          @Value("${h2.datasource.password:}") String h2DatabasePassword,
                          @Value("${h2.datasource.maxcon:2}") int maximumPoolSize)
  {
    this.h2DatabaseUrl = h2DatabaseUrl;
    this.h2DatabaseUsername = h2DatabaseUsername;
    this.h2DatabasePassword = h2DatabasePassword;
    this.maximumPoolSize = maximumPoolSize;
  }

  @Bean(name = "h2DataSource")
  public DataSource h2DataSource()
  {
    log.info("connecting to the h2 database at: {}", h2DatabaseUrl);

    var dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName("org.h2.Driver");
    dataSource.setUrl(h2DatabaseUrl);
    dataSource.setUsername(h2DatabaseUsername);
    dataSource.setPassword(h2DatabasePassword);

    HikariConfig hikariConfig = new HikariConfig();
    hikariConfig.setPoolName("H2 database connection pool");
    hikariConfig.setDataSource(dataSource);
    hikariConfig.setMaximumPoolSize(maximumPoolSize);
    hikariConfig.setMinimumIdle(1);
    hikariConfig.setConnectionTimeout(3000);


    return new HikariDataSource(hikariConfig);
  }

  @Bean(name = "h2EntityManagerFactory")
  public EntityManagerFactory h2EntityManagerFactory(@Qualifier("h2DataSource") DataSource h2DataSource)
  {
    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
    em.setDataSource(h2DataSource);
    em.setPackagesToScan("de.governikus.eumw.databasemigration.entities");
    JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
    em.setJpaVendorAdapter(vendorAdapter);

    em.afterPropertiesSet();
    return em.getObject();
  }

  @Bean(name = "h2TransactionManager")
  public PlatformTransactionManager h2TransactionManager(@Qualifier("h2DataSource") DataSource h2DataSource)
  {
    return new JpaTransactionManager(h2EntityManagerFactory(h2DataSource));
  }
}
