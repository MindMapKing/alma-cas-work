package org.apereo.cas.oidc.token;

import com.google.common.base.Preconditions;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.mfa.MultifactorAuthenticationProperties;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.cas.util.Pac4jUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Patched version of org.apereo.cas.oidc.token.OidcIdTokenGeneratorService v5.3.4
 * Allows creation of JWT even if a service ticket is not available, as is the
 * case when invoking the OIDC <em>Resource Owner Credentials</em> claim, which
 * CAS documents call the "password" grant: 
 * {@code https://host:port/cas/oidc/accessToken? response_type=id_token%20token & grant_type=password & client_id=CLIENT_ID & username=USERNAME & password=PASSWORD & scope=openid%20profile%20profile_full}
 * <p>
 * Also removed dependency on Lombok.
 * <p>
 * See sections marked <em>PATCH</em>.
 * 
 * @author mchavan, 03-Dec-2018
 */
public class OidcIdTokenGeneratorService {

    private final CasConfigurationProperties casProperties;
    private final OidcIdTokenSigningAndEncryptionService signingService;
    private final ServicesManager servicesManager;
    private final String oAuthCallbackUrl;
    private final Logger LOGGER = LoggerFactory.getLogger( OidcIdTokenGeneratorService.class.getSimpleName() );


    public OidcIdTokenGeneratorService(final CasConfigurationProperties casProperties,
                                       final OidcIdTokenSigningAndEncryptionService signingService,
                                       final ServicesManager servicesManager) {
        this.casProperties = casProperties;
        this.signingService = signingService;
        this.servicesManager = servicesManager;
        this.oAuthCallbackUrl = casProperties.getServer().getPrefix()
            + OAuth20Constants.BASE_OAUTH20_URL + '/'
            + OAuth20Constants.CALLBACK_AUTHORIZE_URL_DEFINITION;
    }

    /**
     * Generate string.
     *
     * @param request           the request
     * @param response          the response
     * @param accessTokenId     the access token id
     * @param timeoutInSeconds  the timeoutInSeconds
     * @param responseType      the response type
     * @param registeredService the registered service
     * @return the string
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public String generate(final HttpServletRequest request,
                           final HttpServletResponse response,
                           final AccessToken accessTokenId,
                           final long timeoutInSeconds,
                           final OAuth20ResponseTypes responseType,
                           final OAuthRegisteredService registeredService) {

        if (!(registeredService instanceof OidcRegisteredService)) {
            throw new IllegalArgumentException("Registered service instance is not an OIDC service");
        }

        final OidcRegisteredService oidcRegisteredService = (OidcRegisteredService) registeredService;
        final J2EContext context = Pac4jUtils.getPac4jJ2EContext(request, response);
        final ProfileManager manager = Pac4jUtils.getPac4jProfileManager(request, response);
        final Optional<UserProfile> profile = manager.get(true);

        if (!profile.isPresent()) {
            throw new IllegalArgumentException("Unable to determine the user profile from the context");
        }

        LOGGER.debug("Attempting to produce claims for the id token [{}]", accessTokenId);
        final JwtClaims claims = produceIdTokenClaims(request, accessTokenId, timeoutInSeconds,
            oidcRegisteredService, profile.get(), context, responseType);
        LOGGER.debug("Produce claims for the id token [{}] as [{}]", accessTokenId, claims);

        return this.signingService.encode(oidcRegisteredService, claims);
    }

    /**
     * Produce id token claims jwt claims.
     *
     * @param request          the request
     * @param accessTokenId    the access token id
     * @param timeoutInSeconds the timeoutInSeconds
     * @param service          the service
     * @param profile          the user profile
     * @param context          the context
     * @param responseType     the response type
     * @return the jwt claims
     */
    protected JwtClaims produceIdTokenClaims(final HttpServletRequest request,
                                             final AccessToken accessTokenId,
                                             final long timeoutInSeconds,
                                             final OidcRegisteredService service,
                                             final UserProfile profile,
                                             final J2EContext context,
                                             final OAuth20ResponseTypes responseType) {
        final Authentication authentication = accessTokenId.getAuthentication();
        final Principal principal = authentication.getPrincipal();
        final OidcProperties oidc = casProperties.getAuthn().getOidc();

        final JwtClaims claims = new JwtClaims();
        try {
			claims.setJwtId(getOAuthServiceTicket(accessTokenId.getTicketGrantingTicket()).getKey());
		} 
        catch( java.lang.IllegalStateException e ) {
        	// PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH
        	//
        	// If a service ticket cannot be found an exception is thrown
        	// because the ticket is used to generate the JWT "jti" (ID) claim.
        	// We just catch the exception and provide an alternative ID instead,
        	// so we can support the OIDC "password" grant instead.
        	//
        	// amchavan, 03-Dec-2018
        	
	        final String jwtId = UUID.randomUUID().toString();
	        claims.setJwtId( jwtId );

        	// PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH
		}
        claims.setIssuer(oidc.getIssuer());
        claims.setAudience(service.getClientId());

        final NumericDate expirationDate = NumericDate.now();
        expirationDate.addSeconds(timeoutInSeconds);
        claims.setExpirationTime(expirationDate);
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(oidc.getSkew());
        claims.setSubject(principal.getId());

        final MultifactorAuthenticationProperties mfa = casProperties.getAuthn().getMfa();
        final Map<String, Object> attributes = authentication.getAttributes();

        if (attributes.containsKey(mfa.getAuthenticationContextAttribute())) {
            final Collection<Object> val = CollectionUtils.toCollection(attributes.get(mfa.getAuthenticationContextAttribute()));
            claims.setStringClaim(OidcConstants.ACR, val.iterator().next().toString());
        }
        if (attributes.containsKey(AuthenticationHandler.SUCCESSFUL_AUTHENTICATION_HANDLERS)) {
            final Collection<Object> val = CollectionUtils.toCollection(attributes.get(AuthenticationHandler.SUCCESSFUL_AUTHENTICATION_HANDLERS));
            claims.setStringListClaim(OidcConstants.AMR, val.toArray(new String[]{}));
        }

        claims.setClaim(OAuth20Constants.STATE, attributes.get(OAuth20Constants.STATE));
        claims.setClaim(OAuth20Constants.NONCE, attributes.get(OAuth20Constants.NONCE));
        claims.setClaim(OidcConstants.CLAIM_AT_HASH, generateAccessTokenHash(accessTokenId, service));

        LOGGER.info( " >>> Entry set: " + principal.getAttributes().entrySet() );
        principal.getAttributes().entrySet().stream()
            .filter(entry -> oidc.getClaims().contains(entry.getKey()))
            .forEach(entry -> claims.setClaim(entry.getKey(), convertSingleEntryList( entry )));

        if (!claims.hasClaim(OidcConstants.CLAIM_PREFERRED_USERNAME)) {
            claims.setClaim(OidcConstants.CLAIM_PREFERRED_USERNAME, profile.getId());
        }

        return claims;
    }


	/*
	 *  PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH
	 *  
	 *  In some cases principal attributes are returned as lists of
	 *  a single string instead of just a plain string -- here we cope with that.
	 *  Not pretty but effective.
	 *  
	 *  PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH PATCH
	 */
    private Object convertSingleEntryList( Entry<String, Object> entry ) {
//        final String msg = 
//        		" >>> Entry: " + entry.getKey() + "=" + entry.getValue() + " ("
//        		+ entry.getValue().getClass().getSimpleName() + ")";
//		LOGGER.info( msg );
    	
    	Object ret = entry.getValue();
        if( ret instanceof LinkedList ) {
        	LinkedList<?> t = (LinkedList<?>) ret;
        	if( t.size() == 1 ) {
        		ret = t.get( 0 );
        	}
        }
    	return ret;
    }
    
    
    private Entry<String, Service> getOAuthServiceTicket(final TicketGrantingTicket tgt) {
        final Optional<Entry<String, Service>> oAuthServiceTicket = Stream.concat(
            tgt.getServices().entrySet().stream(),
            tgt.getProxyGrantingTickets().entrySet().stream())
            .filter(e -> servicesManager.findServiceBy(e.getValue()).getServiceId().equals(oAuthCallbackUrl))
            .findFirst();
        Preconditions.checkState(oAuthServiceTicket.isPresent(), "Cannot find service ticket issues to " + oAuthCallbackUrl + " as part of the authentication context");
        return oAuthServiceTicket.get();
    }

    private String generateAccessTokenHash(final AccessToken accessTokenId,
                                           final OidcRegisteredService service) {
        final byte[] tokenBytes = accessTokenId.getId().getBytes(StandardCharsets.UTF_8);
        final String hashAlg;

        switch (signingService.getJsonWebKeySigningAlgorithm()) {
            case AlgorithmIdentifiers.RSA_USING_SHA512:
                hashAlg = MessageDigestAlgorithms.SHA_512;
                break;
            case AlgorithmIdentifiers.RSA_USING_SHA256:
            default:
                hashAlg = MessageDigestAlgorithms.SHA_256;
        }

        LOGGER.debug("Digesting access token hash via algorithm [{}]", hashAlg);
        final byte[] digested = DigestUtils.rawDigest(hashAlg, tokenBytes);
        final byte[] hashBytesLeftHalf = Arrays.copyOf(digested, digested.length / 2);
        return EncodingUtils.encodeUrlSafeBase64(hashBytesLeftHalf);
    }
}

