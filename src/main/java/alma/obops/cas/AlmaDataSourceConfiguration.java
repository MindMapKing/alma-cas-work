package alma.obops.cas;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.orm.jpa.JpaTransactionManager;

import com.mchange.v2.c3p0.ComboPooledDataSource;

/**
 * Configure the application's data source according to ALMA's conventions, e.g.
 * storing the data source parameters in
 * <em>$ACSDATA/config/archiveConfig.properties</em>
 * 
 * @author amchavan
 */

@Configuration
@PropertySource("file:${ACSDATA}/config/archiveConfig.properties")
// We only need archiveConfig.properties, but we could add multiple @PropertySource 
// annotations here, for instance
// @PropertySource("file:${ACSDATA}/config/obopsConfig.properties")
// All properties are added to the environment; properties found in later files
// override the previously defined values
public class AlmaDataSourceConfiguration {
	
	Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	Environment env;
	
	@Bean
//	@ConfigurationProperties(prefix="spring.datasource")
	public DataSource dataSource() {

        String url      = env.getProperty( "archive.relational.connection" );
		String username = env.getProperty( "archive.relational.user" );
		String password = env.getProperty( "archive.relational.passwd" );

		logger.info( " Database URL : " + url );
		logger.info( " Database user: " + username );

		java.util.Properties props = new java.util.Properties();
		props.put("v$session.program", "CAS");

		ComboPooledDataSource dataSource = new ComboPooledDataSource();
		dataSource.setProperties( props );
		dataSource.setUser( username );
		dataSource.setPassword( password );
		dataSource.setJdbcUrl( url );

		return dataSource;
	}
}

