[![Build Status](https://travis-ci.org/looorent/keycloak-micronaut-adapter.svg?branch=master)](https://travis-ci.org/looorent/keycloak-micronaut-adapter)
//// [![Maven Central](https://maven-badges.herokuapp.com/maven-central/be.looorent/keycloak-micronaut-adapter/badge.svg)](http://search.maven.org/#artifactdetails%7Cbe.looorent%7Ckeycloak-micronaut-adapter)

# Keycloak - Micronaut Adapter

On one hand, Micronaut is quite handy to create low footprint memory micro-services. On the other hand, Keycloak is a very useful tool to secure your endpoints using JWT.
This adapter acts as a Middleware for Micronaut that validates HTTP requests to verify their Authorization headers.

The adapter retrieves all public keys from Keycloak automatically and use them to verify each request's token.

All type of validations (JWT parsing, custom validations, headers,...) are implemented and return an HTTP status `401`.

## Install

* For Gradle, add this line to the `dependencies`:
```groovy
compile "be.looorent:keycloak-micronaut-adapter:1.5.1"
```

* or with Maven:
```xml
<dependency>
    <groupId>be.looorent</groupId>
    <artifactId>keycloak-micronaut-adapter</artifactId>
    <version>1.5.1</version>
</dependency>
```

## Compatibility

Tested with:
* Micronaut 1.0.1
* Keycloak 3+ (tested until 6.0.1)
* Java (JDK 8+), Kotlin and Groovy (tested until JDK 12)

## Get Started

### 1) [Optional] Create a validator

If you need to verify specific attributes in the JWT (_e.g._ a client role), you can provide your own implementation of `be.looorent.micronaut.security.TokenValidator`.
A default implementation `be.looorent.micronaut.security.DefaultTokenValidator` is available (and does... nothing!). This one is active when you don't provide your own.

For example, here under is a Kotlin implementation that validates a role `can-do-stuff` for the Keycloak client `a-mobile-client`.

```kotlin
import be.looorent.micronaut.security.DefaultTokenValidator
import be.looorent.micronaut.security.TokenValidator
import io.jsonwebtoken.Claims
import io.micronaut.context.annotation.Replaces
import java.util.Optional.ofNullable
import javax.inject.Singleton

@Singleton
@Replaces(DefaultTokenValidator::class)
class UserValidator : TokenValidator {

    companion object {
        const val USER_ATTRIBUTE = "userId"
        const val CLIENT_ID = "a-mobile-client"
        const val ROLE_REQUIRED = "can-do-stuff"
    }

    override fun validate(tokenContent: Claims) {
        validateUserIdIn(tokenContent)
        validateRoleIn(tokenContent)
    }

    private fun validateUserIdIn(tokenContent: Claims) {
        ofNullable(tokenContent.get(USER_ATTRIBUTE, Integer::class.java))
                .orElseThrow { throw SecurityException("This token does not contain any userId attribute") }
    }

    private fun validateRoleIn(tokenContent: Claims) {
        ofNullable(tokenContent["resource_access"] as Map<String, *>)
                .map { it[CLIENT_ID] as Map<String, List<String>> }
                .map { it["roles"] }
                .filter { it != null && it.contains(ROLE_REQUIRED) }
                .orElseThrow { throw SecurityException("This token does not contain the expected roles") }
    }
}
```

### 2) [Optional] Create a `SecurityContext` factory

A `SecurityContext` is a container for your custom data (included in the Token). If you provide an implementation of `SecurityContextFactory`, you can get data from the token claims and provide them to your controller. Actually, this adapter set the Http Request's attribute `SecurityContext` with an instance of `SecurityContext` (provide your own if required).

For example, here under is a Kotlin implementation that add a `userId` to the Security Context of the HTTP request. This `userId` can be retrieved in the controller using `request.getAttribute("SecurityContext")`.

```kotlin
import be.looorent.micronaut.security.SecurityContextFactory
import be.looorent.micronaut.security.DefaultSecurityContextFactory
import io.jsonwebtoken.Claims
import javax.inject.Singleton

@Singleton
@Replaces(DefaultSecurityContextFactory::class)
internal class UserSecurityContextFactory : SecurityContextFactory {

    companion object {
        const val USER_ID = "userId"
    }

    override fun createSecurityContext(tokenContent: Claims): UserSecurityContext {
        return UserSecurityContext(tokenContent.get(USER_ID, Int::class.java))
    }
}


import be.looorent.micronaut.security.SecurityContext

internal data class UserSecurityContext(
        val userId: Int
): SecurityContext
```

### 3) [Mandatory] Create an HttpServerFilter

To register this adapter as a Micronaut filter, you must specify which controller is affected.
This can be done by implementing an `HttpServerFilter`. Don't worry, everything is already implemented in `be.looorent.micronaut.security.SecurityFilter`. However, you must specify a class annotated with `@Filter` to setup this filter.

For instance, here under is a Kotlin implementation that secures all endpoints under the path `/api`.

```kotlin
import be.looorent.micronaut.security.SecurityFilter
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import org.reactivestreams.Publisher

@Filter(value = [
    "/api/**"
])
internal class UserSecurityFilter (
        private val filter: SecurityFilter
): HttpServerFilter {
    override fun doFilter(request: HttpRequest<*>, chain: ServerFilterChain): Publisher<MutableHttpResponse<*>> {
        return filter.doFilter(request, chain)
    }
}
```

### 4) [Mandatory] Setup properties

These options do not have any default value and MUST be setup.
They can be setup using java properties (in your `application.yml`, as environment variables, ...

| Option | ENV equivalent | Type | Required? | Description  | Example |
| ---- | ----- | ------ | ----- | ------ | ----- |
| `keycloak.realm-id` | `KEYCLOAK_REALM_ID`| String | Required | The base url where your Keycloak server is located. This value can be retrieved in your Keycloak client configuration. | `http://auth:8080` |
| `keycloak.base-url` | `KEYCLOAK_BASE_URL`| String | Required | The name of your Keycloak realm (not id, actually). This value can be retrieved in your Keycloak client configuration. | `stuff` |
| `keycloak.eager-load-public-keys` | `KEYCLOAK_EAGER_LOAD_PUBLIC_KEYS`| Boolean | Required | Whether or not the Keycloak public keys are retrieved at start up. | `false` |
| `security.token.issuer` | `SECURITY_TOKEN_ISSUER`| String | Required | The issuer that will be validated in your JWT. | `http://auth/keycloak` |

## Eager loading public keys

If Keycloak is available when your Micronaut server starts, you probably should eager load Keycloak's public keys at startup.

You can eager load them by setting the property `eager-load-public-keys` to `true`.

If eager loading is disabled, the first token validation will retrieve the public keys from Keycloak. This can be a time-consuming process (multiple seconds). Eager loading public keys can solve this issue (however, startup time will be longer).

## Error handling

### Status code

These error HTTP statuses can be returned for each authenticated request:
* `401` when the token is refused. The reason is written in the response body. These reasons are:
    * `jws_unsupported_by_application` : when receiving a JWT in a particular format/configuration that does not match the format expected by the application.
    * `jws_malformed` : indicates that a JWT was not correctly constructed and should be rejected.
    * `jwt_expired` : indicates that a JWT was accepted after it expired and must be rejected.
    * `jwt_wrong_signature` :  indicates that either calculating a signature or verifying an existing signature of a JWT failed.
    * `authorization_header_missing`: indicates that no Bearer Token has been provided through the Authorization header.
    * `authorization_header_wrong_format`:
    * `authorization_header_wrong_scheme`:
    * Another unexpected message

## Logging

This library uses log4j with the prefixes `be.looorent.micronaut.security` and `be.looorent.keycloak`.

## How to deploy a new version to Maven central

Following this [great article](http://nemerosa.ghost.io/2015/07/01/publishing-to-the-maven-central-using-gradle/), you should configure your `./gradle/gradle.propreties` file and then:

```
$ ./gradlew -Prelease uploadArchives closeAndPromoteRepository
```

# Future work

* configure filter pattern using property, possible?