package uk.co.foonkiemonkey.micronaut.security

import spock.lang.Shared
import spock.lang.Specification

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey

import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.JWT_EXPIRED
import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.JWT_MALFORMED
import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.JWT_UNSUPPORTED
import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.JWT_WRONG_KID
import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.JWT_WRONG_SIGNATURE
import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.VALIDATION

class TokenParserImplSpec extends Specification {

    private static final String VALID_ISSUER = "https://keycloak.org/auth"
    private static final String VALID_SUBJECT = "41598cfa-2aed-487b-b854-9e5c8271daa4"
    private static final String VALID_KID = "5f4c7777-de12-4f10-ad70-2a8290d2af08"

    @Shared
    private wrongKeyPair = createKeyPair()

    def tokenFactory = new TokenFactory(VALID_KID, VALID_ISSUER, VALID_SUBJECT)

    Map<String, PublicKey> keysPerId = [ "5f4c7777-de12-4f10-ad70-2a8290d2af08" : tokenFactory.publicKey, "96f976d9-ef85-4a9b-aa6a-a4982b1fd7ec": wrongKeyPair.public ]

    def publicKeyService = new InMemoryPublicKeyService(keysPerId)
    def publicKeyResolver = new PublicKeyResolver(publicKeyService)
    def securityContextFactory = new SubjectSecurityContextFactory()
    def validator = new SubjectTokenValidator(VALID_SUBJECT)
    def parser = new TokenParserImpl(VALID_ISSUER, publicKeyResolver, securityContextFactory, validator)

    def "construct parser with an empty issuer throws an exception"(String wrongIssuer) {
        when:
        new TokenParserImpl(wrongIssuer, publicKeyResolver, securityContextFactory, validator)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "Property 'security.token.issuer' (string) must be set"

        where:
        wrongIssuer << ["", null]
    }

    def "construct parser without resolver throws an exception"() {
        when:
        new TokenParserImpl(VALID_ISSUER, null, securityContextFactory, validator)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "No implementation of PublicKeyResolver has been found"
    }

    def "construct parser without securityContextFactory throws an exception"() {
        when:
        new TokenParserImpl(VALID_ISSUER, publicKeyResolver, null, validator)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "No implementation of SecurityContextFactory has been found"
    }

    def "construct parser without validator throws an exception"() {
        when:
        new TokenParserImpl(VALID_ISSUER, publicKeyResolver, securityContextFactory, null)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "No implementation of TokenValidator has been found"
    }

    def "parse an unsupported jwt throws an exception"() {
        given:
        String token = tokenFactory.createTokenWithoutSignature()

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == JWT_UNSUPPORTED
    }

    def "parse an malformed jwt throws an exception"() {
        given:
        String token = tokenFactory.createMalformedToken()

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == JWT_MALFORMED
    }

    def "parse an wrongly signed jwt throws an exception"() {
        given:
        String token = tokenFactory.createTokenWronglySigned(wrongKeyPair.private)

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == JWT_WRONG_SIGNATURE
    }

    def "parse an expired jwt throws an exception"() {
        given:
        String token = tokenFactory.createExpiredToken()

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == JWT_EXPIRED
    }

    def "parse a jwt not valid against validator throws an exception"() {
        given:
        String token = tokenFactory.createTokenWithOtherSubject()

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == VALIDATION
    }

    def "parse a valid token works fine"() {
        given:
        String token = tokenFactory.createValidToken()

        when:
        SecurityContext context = parser.parse(token)

        then:
        context != null
        context instanceof SubjectSecurityContext
        ((SubjectSecurityContext) context).subject == VALID_SUBJECT
    }

    def "parse a valid token with an unkwown kid throws an exception"() {
        given:
        def token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJXX2I2YWlUZVU4a1JvRXp3eGluN1VMcmd2Ri1WTkFIU1ZKT2pTc2VTZmt3In0.eyJqdGkiOiJkYTAzNTQzNy03Y2NhLTRhYzMtOTc0My0xZTkyN2FhODg5ZmUiLCJleHAiOjE1MzE4NDU4MzEsIm5iZiI6MCwiaWF0IjoxNTMxODQ0MDMxLCJpc3MiOiJodHRwOi8vYXV0aGVudGljYXRpb24vYXV0aC9yZWFsbXMvb3JnYW5pc2F0aW9ucyIsImF1ZCI6InBhcmtpbmctYWNjZXNzLWFwaSIsInN1YiI6Ijg0N2M1ZGQyLWFkOWQtNDhkYi05MWQ0LTYxODNlMjRlNWZkMSIsInR5cCI6IkJlYXJlciIsImF6cCI6InBhcmtpbmctYWNjZXNzLWFwaSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImM5YjJkYjNmLTk1NmUtNDA4ZS1hM2RiLTUyNDYxZGE1MjQwYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZXNvdXJjZV9hY2Nlc3MiOnsicGFya2luZy1hY2Nlc3MtYXBpIjp7InJvbGVzIjpbInBhcmtpbmctYWNjZXNzLWFwaSJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiIiLCJvcmdhbmlzYXRpb25JZCI6NDJ9.cZTogVKIggiyMNkg1dIAHnr1_7HbzVvf2gU48ivH3jh-sE4D2YKFvQn4YEq2JhYIVr6s3TN8MVzP9FlZ1EVkDf-t_QY5Umb67-fu2BN4GXtpN1VRglQvXh6PJEPNqXthueD2Z8fShaUV1BbugwOR1UDLML5LiFsfUgY-bPUq6m2XOBL68jYSqLKJm-HDus2gdEY6V2l4dfsdsSEwOCHBJHsskweTuoFvpZXwivfHdjV8mt6kU9e90gFPZRmpcM6NM-pTtVBQrnGuRJBWWFCbrKy2ttmx5I8Xl3qXZ61z8vLO6CPAEbU9VGf6szs8gf4WP8JFueS-t0Wqc_DIDCBsfQ"

        when:
        parser.parse(token)

        then:
        SecurityException exception = thrown()
        exception.type == JWT_WRONG_KID
    }

    private static KeyPair createKeyPair() {
        def generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(1024)
        generator.generateKeyPair()
    }
}
