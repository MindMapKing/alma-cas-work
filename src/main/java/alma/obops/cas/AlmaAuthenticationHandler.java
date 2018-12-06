package alma.obops.cas;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import javax.xml.bind.DatatypeConverter;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

// refer to https://apereo.github.io/2017/02/02/cas51-authn-handlers/

@Component
public class AlmaAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    private static final String SELECT_ACCOUNT = 
        "SELECT account_id, email, firstname, lastname " +
        "FROM   account " + 
        "WHERE  account_id = ? " + 
        "AND    active = 'T' " +
        "AND    password_digest = ?";

    private static final String SELECT_ROLES = 
        "SELECT    application, name " + 
        "FROM      role " +
        "LEFT JOIN account_role ON role.role_no = account_role.role_no " + 
        "WHERE     account_role.account_id = ? " +
        "ORDER BY  application, name";
    
    Logger log = LoggerFactory.getLogger( AlmaAuthenticationHandler.class.getSimpleName() );

    @Autowired
    private Environment env;
    
    @Autowired
    private DataSource dataSource;
    
    private JdbcTemplate jdbcTemplate;

    public AlmaAuthenticationHandler( String name, 
                                      ServicesManager servicesManager, 
                                      PrincipalFactory principalFactory,
                                      Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @PostConstruct
    private void initJdbcTemplate() {
        jdbcTemplate = new JdbcTemplate( dataSource );
        // String url = env.getProperty( "archive.relational.connection" );
        // log.info( " >>> alma.datasource.url={}", url );
    }

    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal (

    	final UsernamePasswordCredential credential,
        final String originalPassword) throws GeneralSecurityException, PreventedException {
    	log.info( " >>> credential: {}", credential );
        
    	String username = credential.getUsername().trim();
		String password  = credential.getPassword().trim();
		String password_digest = computeMD5Hash( password ); // Compute MD5 hash of the password
		log.info( " >>> password_digest: {}", password_digest );
		
		try {
		    
		    // query DB for username
		    Map<String,Object> dbCredentials =
		        jdbcTemplate.queryForMap( SELECT_ACCOUNT, username, password_digest );
		    Object t = dbCredentials.get( "account_id" );
		    if( t == null ) {
		        throw new FailedLoginException( "Invalid credentials" );
		    }
		    
		    Map<String, Object> attributes = new HashMap<>();
		    attributes.put( "email",     dbCredentials.get( "email" ));
		    attributes.put( "firstname", dbCredentials.get( "firstname" ));
		    attributes.put( "lastname",  dbCredentials.get( "lastname" ));
		
		    // query DB for roles
		    List<String> roleList = new ArrayList<>();
		    List<Map<String,Object>> rows = 
		        jdbcTemplate.queryForList( SELECT_ROLES, username );
		    for( Map<String,Object> row : rows ) {
		        String name        = row.get( "name" ).toString().trim();
		        String application = row.get( "application" ).toString().trim();
		        roleList.add( application + "/" + name );
		    }
		    log.info( " >>> roleList: {}", roleList );
		
		    attributes.put( "roles", roleList );
		
		    log.info( ">>> attributes: {}", attributes.toString() );
		    Principal principal = principalFactory.createPrincipal( username, attributes );
			return createHandlerResult( credential, principal );            
		}
		catch( Exception e ) {
			log.error( e.getMessage(), e );
		    throw new RuntimeException( e );
		}
    }

    // From https://www.baeldung.com/java-md5
	private String computeMD5Hash( String password ) {
		try {
            MessageDigest md = MessageDigest.getInstance( "MD5" );
            md.update(password.getBytes());
            byte[] digest = md.digest();
            return DatatypeConverter.printHexBinary( digest ).toLowerCase();
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
