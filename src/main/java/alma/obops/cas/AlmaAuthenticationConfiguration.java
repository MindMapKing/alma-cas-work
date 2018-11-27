package alma.obops.cas;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;

@Configuration( "AlmaAuthenticationConfiguration" )
@EnableConfigurationProperties( CasConfigurationProperties.class )
public class AlmaAuthenticationConfiguration implements AuthenticationEventExecutionPlanConfigurer {
    // @Autowired
    // private CasConfigurationProperties casProperties;

    @Bean
    public AuthenticationHandler esoAuthenticationHandler() {
        final AlmaAuthenticationHandler handler =
                new AlmaAuthenticationHandler( "Alma Auth Handler", null, null, null );
        /*
            Configure the handler by invoking various setter methods.
            Note that you also have full access to the collection of resolved CAS settings.
            Note that each authentication handler may optionally qualify for an 'order` 
            as well as a unique name.
        */
        return handler;
    }

    @Override
    public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
        plan.registerAuthenticationHandler(esoAuthenticationHandler());
    }
}
