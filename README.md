# ALMA CAS workspace

To experiment with CAS **TODO**

## Build

Environment specific configuration files are in
* src/main/resources/application-int.properties
* src/main/resources/application-prod.properties

Active profile is currently hardcoded to _int_ in `src/main/resources/bootstrap.properties` and includes an Oracle connection to _ora12c2.hq.eso.org_.

**TODO** Externalize that to archiveConfig.properties

To build run `mvn clean package` from the command line, it will produce `./target/cas.war`

## Configure

* Create directory _$ACSDATA/config/cas/services_
* Copy _etc/cas/config/cas.properties_ to _$ACSDATA/config/cas_ 
* Generate a private/public JSON keypair set for the tokens and store it in 
  _$ACSDATA/config/cas/oidc-keystore.jwks_. The keypair set can be generated
  with some Web service like https://mkjwk.org (for testing only) or https://connect2id.com/products/nimbus-jose-jwt/generator (in production). It looks like this:  
  ```
  {
	"keys": [
		{
		"kty": "RSA",
		"d": "fgP6WU2n7uVMs...VADspF2Q",
		"e": "AQAB",
		"use": "sig",
		"kid": "alma.obops.cas",
		"alg": "RS256",
		"n": "ilDEzMlLAvEzw..._QhkybvcJkMQw"
		}
	]
  }
  ```

* Create a basic service with the following naming convention:  
  `fileName = serviceName + "-" + serviceNumericId + ".json"`  
  for instance _demoOIDC-1000.json_:  
  ```
  {
  "@class": "org.apereo.cas.services.OidcRegisteredService",
  "clientId": "demoOIDC",
  "clientSecret": "s3cr3t",
  "serviceId": "^https://app.example.com/redirect",
  "signIdToken": true,
  "implicit": true,
  "bypassApprovalPrompt": false,
  "name": "Demo app",
  "id": 1000,
  "evaluationOrder": 100,
  "encryptIdToken": false,
  "scopes": [ "java.util.HashSet",
    [ "openid", "profile", "profile_full" ]
  ]
  }
  ```

## Security configuration

### SSL certificate
CAS must work via HTTPS and requires a secure environment to be configured for Spring Boot— see https://www.thomasvitale.com/https-spring-boot-ssl-certificate

You'll need a SSL certificate in a keystore. If you don't have one you can create it:  
`keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650`  
Use _changeit_ when requested a password.  
Move _keystore.p12_, the generated keystore, to _$ACSDATA/config/cas_

To view the contents of the keystore: `keytool -list -v -storetype pkcs12 -keystore $ACSDATA/config/cas/keystore.p12`

### Spring Boot properties

Make sure your _cas.properties_ file includes the following Spring Boot properties:
```
security.require-ssl=true
server.ssl.key-store-type=PKCS12
server.ssl.key-store=file:${ACSDATA}/config/cas/keystore.p12
server.ssl.key-store-password=changeit
server.ssl.key-alias=tomcat
```

### Import the certificate inside the JRE keystore

You'll need to make the JRE trust your self-signed certificate. First of all, you need to extact it from the keystore:  
`keytool -export -keystore $ACSDATA/config/cas/keystore.jks -alias tomcat -file certificate.crt`  

#### Linux and MacOS

You then need to locate your JDK home. On MacOS you can use:  
`export JAVA_HOME=$(/usr/libexec/java_home)`

On Linux it depends on how your JVM is installed, it could be something like _/usr/lib/jvm/java-1.8.0-openjdk-1.8.0...._

Then (you'll probably need _sudo_ privileges):  
`sudo keytool -importcert -file certificate.crt -alias tomcat -keystore $JAVA_HOME/jre/lib/security/cacerts`

If everything went right, you’d see the message _Certificate was added to keystore_.

#### Windows

Assuming your JDK is _1.8.0_162_:
```
cd "c:\Program Files\Java\jdk1.8.0_162"
bin\keytool.exe -importcert -file path-to-certificate.crt -alias tomcat -keystore jre\lib\security\cacerts
```

## Run

* `export _JAVA_OPTIONS="-Dcas.standalone.config=$ACSDATA/config"`
* `java -jar target/cas.war`

## Basic test

In the following examples, replace _ma24088.ads.eso.org_ with your fully qualified hostname; do not use _localhost_. 

In your browser, open a new incognito/anonymous window or clean all cookies originating from your domain, then: 
* Access the login page as _https://ma24088.ads.eso.org:8019/cas/login_ and login with your credentials
* Log out again at _https://ma24088.ads.eso.org:8019/cas/logout_

## OAuth2

### Implicit authorization flow

From a browser, open a new incognito/anonymous window and navigate to https://ma24088.ads.eso.org:8019/cas/oauth2.0/authorize?response_type=token&client_id=demoOIDC&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect

You will be redirected to _example.com_: the URL will contain the OAuth access token:  
`https://app.example.com/redirect#access_token=AT-14-Sdj1AA...&token_type=bearer&expires_in=7200`

## OIDC

### Implicit authorization flow

Verify that OpenID Connect is functioning by initiating an [_Implicit_ authorization flow](https://developer.okta.com/blog/2018/05/24/what-is-the-oauth2-implicit-grant-type) with the URL (replace _ma24088.ads.eso.org_, with your hostname, _do not_ use localhost):

https://ma24088.ads.eso.org:8019/cas/oidc/authorize?response_type=id_token%20token&client_id=demoOIDC&scope=openid%20profile%20profile_full&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect

Optional URL parameters are _state_ and _nonce_, for instance `...&state=3km36n5yp2l9h26&nonce=po7s2tr6wnc8xs2` — see [here](https://stackoverflow.com/questions/46844285/difference-between-oauth-2-0-state-and-openid-nonce-parameter-why-state-cou) for more info.

You should be taken to CAS' login page. Once the authentication/authorization procedure is completed you should be redirected to _app.example.com_ with a URTL including an *id_token*, a JWT. Copy the token string from the URL and paste it into e.g. the debugger of https://jwt.io to see its contents.

For more info about OIDC endpoints, see https://apereo.github.io/cas/5.0.x/installation/OIDC-Authentication.html


## Notes

* Package `alma.obops.cas` contain ALMA- and Oracle-specific code for verifying
  credentials and retrieving user roles.

* _Very_ useful documentation
   * About CAS/OIDC: https://mirzlab.github.io/2017/07/16/cas5-oidc-provider/
   * About _keytool_, etc: https://www.sslshopper.com/
