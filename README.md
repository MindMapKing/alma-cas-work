# ALMA CAS  — OAuth 2.0 — OpenID Connect Server

A CAS server implementing OAauth 2.0 (OAuth2) and 
OpenID Connect (OIDC) in addition
to CAS' own protocol.

## Build

Configuration files are 
* src/main/resources/bootstrap.properties
* src/main/resources/application-base.properties

Active profile is currently hardcoded to _base_ in `src/main/resources/bootstrap.properties`.

To build run `mvn clean package` from the command line, it will produce `./target/cas-oidc-server-<version>.war`, where _&lt;version>_ is something like _OBOPS-2019.02_

## Configure

* Create directory _$ACSDATA/config/cas_ and copy the contents of the _config_ directory to that. (Note the _config/services_ directory.)

* The config directory includes a private/public JSON keypair set 
  for the tokens in 
  _$ACSDATA/config/cas/oidc-keystore.jwks_. The keypair set can be regenerated
  with some Web service like https://mkjwk.org or https://connect2id.com/products/nimbus-jose-jwt/generator (in production). It looks like this:  
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
  **NOTE** The keypair set is used for signing the JWTs generated buy OAuth2/OIDC. To allow a distributed OIDC service
  _the set should be shared by all participating instances_.

* The _config/services_ directory includes:
  * _generic-0.json_: allows any application to participate in SSO using the CAS protocol
  * _demoOIDC-1000.json_: A basic, demo OAuth2/OIDC service following the naming convention:  
  `fileName = serviceName + "-" + serviceNumericId + ".json"`
  * _RegexRegisteredService-4252....json_: generated by CAS itself for obscure purposes

* Database connection configuration follows the ALMA conventions and is externalized to
  _$ACSDATA/config/archiveConfig.properties_.
  Relevant properties are (with example values):
  ```
  archive.relational.connection = jdbc:oracle:thin:@xyz.example.com:1521/ABCD
  archive.relational.user = someuser
  archive.relational.passwd = s0me/passWD
  ```

## Security configuration

### SSL certificate
CAS _must_ be reached via HTTPS and requires a secure environment to be configured for Spring Boot — see https://www.thomasvitale.com/https-spring-boot-ssl-certificate

You'll need a SSL certificate in a keystore and one is provided in the _config_ directory.  
You you can recreate it as well:  
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

If you have a self-signed certificate you'll need to make the JRE trust it. First of all, you need to extact it from the keystore:  
`keytool -export -keystore $ACSDATA/config/cas/keystore.p12 -alias tomcat -file certificate.crt`  
You then need to locate your JDK home and import the certificate.

#### Linux and MacOS 

On MacOS: `export JAVA_HOME=$(/usr/libexec/java_home)`

On Linux the value of JAVA_HOME depends on how your JVM is installed, it could be something like _/usr/lib/jvm/java-1.8.0-openjdk-1.8.0...._

Then (you'll probably need _sudo_ privileges):  
`sudo keytool -importcert -file certificate.crt -alias tomcat -keystore $JAVA_HOME/jre/lib/security/cacerts`

If everything went right, you’d see the message _Certificate was added to keystore_.

#### Windows

Assuming your JDK is _1.8.0_162_:
```
cd "c:\Program Files\Java\jdk1.8.0_162"
bin\keytool.exe -importcert -file path-to-certificate.crt -alias tomcat -keystore jre\lib\security\cacerts
```

## Launch the CAS/OAuth/OIDC server

The CAS application will write its log files to `/var/log/cas`, make sure that directory exists and is writable. (See _src/main/resources/log4j2.xml_ to change that path.)

* `export _JAVA_OPTIONS="-Dcas.standalone.configurationDirectory=$ACSDATA/config"`
* `java -jar target/target/cas-oidc-server-<version>.war`

**NOTE** In the following examples, replace _ma24088.ads.eso.org_ with the fully qualified hostname of the machine running the CAS server; never use _localhost_. 

**NOTE** You may also want to open a new incognito/anonymous window for the examples to avoid old cookies to interfere.

## Basic test

* Access the login page as _https://ma24088.ads.eso.org:8019/cas/login_ and login with your credentials
* Log out again at _https://ma24088.ads.eso.org:8019/cas/logout_

## OAuth2

See [here](https://alexbilbie.com/guide-to-oauth-2-grants/) for a description of
the OAuth2/OIDC grant (flow) types.

### Implicit Authorization grant (GET)

See [here](https://developer.okta.com/blog/2018/05/24/what-is-the-oauth2-implicit-grant-type)
for more info on the _Implicit Authorization_ grant type. 

Navigate to:  
`https://ma24088.ads.eso.org:8019/cas/oauth2.0/authorize?response_type=token&client_id=demoOIDC&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect`

After login you will be redirected to _example.com/redirect_: the URL will contain the OAuth2 access token:  
`https://app.example.com/redirect#access_token=AT-14-Sdj1AA...&token_type=bearer&expires_in=7200`

### Authorization Code grant

See
[here](https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type)
for for more info on the _Authorization Code_ grant type.

In a browser navigate to `https://ma24088.ads.eso.org:8019/cas/oauth2.0/authorize?response_type=code&client_id=demoOIDC&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect`, will redirect to login page, then to `https://app.example.com/redirect?code=OC-10-1jHfj....` with some authorization code.

**NOTE** The authorization code (`OC-10-1jHfj....`) has limited validity, please perform the next step(s) within a minuto or so.

Query the auth server with that auth code:
```shell
curl -k -u demoOIDC:s3cr3t \
  https://ma24088.ads.eso.org:8019/cas/oauth2.0/accessToken \
	  -d grant_type=authorization_code \
	  -d redirect_uri=https://app.example.com/redirect \
	  -d code=OC-10-1jHfj....
```
Will return an access token:
`{"access_token":"AT-11-BHoGu4r..." ...}`

(Alternatively, you can navigate to  
`https://ma24088.ads.eso.org:8019/cas/oauth2.0/accessToken?grant_type=authorization_code&client_id=demoOIDC&client_secret=s3cr3t&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect&code=OC-10-1jHfj....`  
in a browser, and you should get the same access token.)

With that token you for instance [retrieve the user profile](#user-profile).


### Resource Owner Credentials grant (_Password grant_)

See [here](https://oauthlib.readthedocs.io/en/latest/oauth2/grants/password.html)
for for more info on the _Resource Owner Credentials_ grant (called _Password grant_ in the CAS documentation).

You can obtain an access token passing the credentials of a Resource Owner (end user) in the URL:  
`https://ma24088.ads.eso.org:8019/cas/oauth2.0/accessToken?grant_type=password&client_id=demoOIDC&username=...&password=...`


### Client Credentials grant

You can obtain an access token passing the credentials of a Client (application) in the URL:  
`https://ma24088.ads.eso.org:8019/cas/oauth2.0/accessToken?grant_type=client_credentials&client_id=demoOIDC&client_secret=s3cr3t`


### User profile

Once you have an access token you can retrieve the profile of the logged-in user:  
`https://ma24088.ads.eso.org:8019/cas/oauth2.0/profile?response_type=token&client_id=demoOIDC&access_token=AT-14-Sdj1AA..`  
Example:
```
{
  "givenName" : "ObOps",
  "lastName" : "Subsystem",
  "mail" : "obops1183@noname.domain.org",
  "roles" : [ "ARCHIVE/ROLE_SOURCECAT_ADMIN", ... ],
  ...
  "id" : "obops"
}
```

Alternatively, you can pass the access token in an HTTP Header: `Authorization: Bearer AT-14-Sdj1AA...`

**NOTE** If you obtained the access token by way of a Client Credentials grant the profile will only include the client ID.

## OIDC

See [here](https://alexbilbie.com/guide-to-oauth-2-grants/) for a description of
the OAuth2/OIDC grant (flow) types.

For more info about OpenID Connect endpoints, see [here](https://apereo.github.io/cas/5.3.x/installation/OIDC-Authentication.html).

### Implicit Authorization grant

Navigate to:  
`https://ma24088.ads.eso.org:8019/cas/oidc/authorize?response_type=id_token%20token&client_id=demoOIDC&scope=openid%20profile%20profile_full&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect`

You should be taken to CAS' login page. Once the authentication/authorization procedure is completed you should be redirected to _app.example.com_ with a URL including an *id_token*, a JWT. Copy the token string from the URL and paste it into e.g. the debugger of https://jwt.io to see its contents.

**NOTE** URL parameters _state_ and _nonce_ are optional, for instance `...&state=3km36n5yp2l9h26&nonce=po7s2tr6wnc8xs2` — see [here](https://stackoverflow.com/questions/46844285/difference-between-oauth-2-0-state-and-openid-nonce-parameter-why-state-cou) for more info.

### Authorization Code grant

See
[here](https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type)
for for more info on the _Authorization Code_ grant type.

In a browser navigate to `https://ma24088.ads.eso.org:8019/cas/oidc/authorize?response_type=code&client_id=demoOIDC&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect`, will redirect to login page, then to `https://app.example.com/redirect?code=OC-17-i43YO...` with some authorization code.

**NOTE** The authorization code (`OC-17-i43YO...`) has limited validity, please perform the next step(s) within a minuto or so.

Query the auth server with that auth code:
```shell
curl -k -u demoOIDC:s3cr3t \
  https://ma24088.ads.eso.org:8019/cas/oidc/token \
	  -d grant_type=authorization_code \
	  -d redirect_uri=https://app.example.com/redirect \
	  -d code=OC-17-i43YO....
```
Will return an access token and an ID token (JWT):
`{"access_token":"AT-13-fyPZz...","id_token":"eyJhbGciOi..."}`

(Alternatively, you can navigate to  
`https://ma24088.ads.eso.org:8019/oidc/token?grant_type=authorization_code&client_id=demoOIDC&client_secret=s3cr3t&redirect_uri=https%3A%2F%2Fapp.example.com%2Fredirect&code=OC-10-1jHfj....`  
in a browser, and you should get the same tokens.)

### Client Credentials grant

You can obtain an JWT ID token passing the credentials of a Client (application) in the URL:  
`https://ma24088.ads.eso.org:8019/cas/oidc/token?response_type=id_token%20token&grant_type=password&client_id=demoOIDC&username=...&password=...`


That will return a JSON structure including the JWT:  
```
{
  "access_token": "AT-1-DJAub2UhX2ftcOyJMbHyNPYG5MnBSN7f",
  "token_type": "bearer",
  "expires_in": 28800,
  "id_token": "eyJhbGciOiJSUzI1NiIsI..."
}
```

## Notes

* Java package `alma.obops.cas` contain ALMA- and Oracle-specific code for verifying credentials and retrieving user roles.

* Java packages `org.apereo.cas...` contain patched versions of the CAS source code.

* _Very_ useful documentation
   * About CAS/OIDC: https://mirzlab.github.io/2017/07/16/cas5-oidc-provider/
   * About _keytool_, etc: https://www.sslshopper.com/
