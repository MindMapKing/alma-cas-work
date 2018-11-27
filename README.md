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

## Run

* Copy _etc/cas/config/cas.properties_ to _$ACSDATA/config_ 
* `export _JAVA_OPTIONS="-Dcas.standalone.config=$ACSDATA/config"`
* `java -jar target/cas.war`

## Notes

* Package `alma.obops.cas` contain ALMA- and Oracle-specific code for verifying
  credentials and retrieving user roles.