# ALMA CAS workspace

To experiment with CAS **TODO**

## Build

Environment specific configuration files are in
* src/main/resources/application-int.properties
* src/main/resources/application-prod.properties

Active profile is currently hardcoded to _int_ in `src/main/resources/bootstrap.properties`

To build: 

`mvn clean && mvn package`

Produces `target/cas.war`

## Configure

* Create directory _$ACSDATA/config/cas/services_
* Copy _etc/cas/config/cas.properties_ to _$ACSDATA/config/cas_ 
* Generate a private/public keypair set (JSON) and store it in 
  _$ACSDATA/config/cas/oidc-keystore.jwks_. The keypair set can be generated
  with some Web service like https://mkjwk.org (for testing only! Use better alternatives in production). It looks like this:  
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

* Create a cert -- see https://www.thomasvitale.com/https-spring-boot-ssl-certificate/

* Install (MacOS: $(/usr/libexec/java_home)/jre/lib/security/cacerts)
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt  --- NO EMAIL

openssl x509 -in certificate.crt -text -noout -- should show CN=ma24088.ads.eso.org

sudo keytool -import -trustcacerts -keystore $(/usr/libexec/java_home)/jre/lib/security/cacerts  -storepass changeit -noprompt -file certificate.crt

## Run
* `export _JAVA_OPTIONS="-Dcas.standalone.config=$ACSDATA/config"`
* `java -jar target/cas.war`

Access the login page as _https://ma24088.ads.eso.org:8019/cas/login_

## OIDC

* https://ma24088.ads.eso.org:8019/cas/oidc/authorize?response_type=id_token%20token&client_id=demoOIDC&scope=openid%20profile%20profile_full&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect&state=3km36n5yp2l9h26&nonce=po7s2tr6wnc8xs2
## Notes

* Package `alma.obops.cas` contain ALMA- and Oracle-specific code for verifying
  credentials and retrieving user roles.