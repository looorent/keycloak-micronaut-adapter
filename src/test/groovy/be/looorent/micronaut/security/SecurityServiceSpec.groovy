package be.looorent.micronaut.security

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import spock.lang.Specification

import static be.looorent.micronaut.security.SecurityErrorType.*

class SecurityServiceSpec extends Specification {

    private static final String VALID_ISSUER = "https://keycloak.org/auth"
    private static final String VALID_SUBJECT = "41598cfa-2aed-487b-b854-9e5c8271daa4"
    private static final String VALID_KID = "5f4c7777-de12-4f10-ad70-2a8290d2af08"

    def factory = new TokenFactory(VALID_KID, VALID_ISSUER, VALID_SUBJECT)
    def parser = Mock(TokenParser)
    def service = new SecurityService(parser)

    def "construct parser without parser throws an exception"() {
        when:
        new SecurityService(null)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "No implementation of TokenParser has been found"
    }

    def "readAndVerifyTokenIn a request without Authorization Header throws an exception"() {
        given:
        HttpRequest<?> request = createRequestWithHeaders([Accept: "json/application"])

        when:
        def context = service.readAndVerifyTokenIn(request)
            .onErrorReturn { e -> e }
            .firstElement()
            .blockingGet()

        then:
        context != null
        context instanceof FailedSecurityContext
        !context.unexpected
        context.exception.type == AUTHORIZATION_HEADER_MISSING
    }

    def "readAndVerifyTokenIn a request with wrong Authorization format throws an exception"() {
        given:
        HttpRequest<?> request = createRequestWithHeaders([Authorization: "test"])

        when:
        def context = service.readAndVerifyTokenIn(request)
            .onErrorReturn { e -> e }
            .firstElement()
            .blockingGet()

        then:
        context != null
        context instanceof FailedSecurityContext
        !context.unexpected
        context.exception.type == AUTHORIZATION_HEADER_WRONG_FORMAT
    }

    def "readAndVerifyTokenIn a request with wrong Authorization scheme throws an exception"() {
        given:
        HttpRequest<?> request = createRequestWithHeaders([Authorization: "WrongScheme test"])

        when:
        def context = service.readAndVerifyTokenIn(request)
            .onErrorReturn { e -> e }
            .firstElement()
            .blockingGet()

        then:
        context != null
        context instanceof FailedSecurityContext
        !context.unexpected
        context.exception.type == AUTHORIZATION_HEADER_WRONG_SCHEME
    }

    def "readAndVerifyTokenIn a request with wrong Token throws the parser exception"(SecurityErrorType parsingError) {
        given:
        String token = factory.createValidToken()
        HttpRequest<?> request = createRequestWithHeaders([Authorization: "Bearer ${token}"])
        parser.parse(token) >> { throw new SecurityException(parsingError) }

        when:
        def context = service.readAndVerifyTokenIn(request)
            .onErrorReturn { e -> e }
            .firstElement()
            .blockingGet()

        then:
        context != null
        context instanceof FailedSecurityContext
        !context.unexpected
        context.exception.type == parsingError

        where:
        parsingError << [JWT_UNSUPPORTED, JWT_MALFORMED, JWT_WRONG_SIGNATURE, JWT_EXPIRED, VALIDATION]
    }

    def "readAndVerifyTokenIn a request with a valid Authorization Header returns a SecurityContext"() {
        given:
        def token = factory.createValidToken()
        HttpRequest<?> request = createRequestWithHeaders([Authorization: "Bearer ${token}"])
        def expectedContext = new SubjectSecurityContext("test")
        parser.parse(token) >> expectedContext

        when:
        def contextFound = service.readAndVerifyTokenIn(request)
                .onErrorReturn { e -> e }
                .firstElement()
                .blockingGet()

        then:
        contextFound != null
        contextFound == expectedContext
    }

    private HttpRequest<?> createRequestWithHeaders(Map<String, String> headersValue) {
        def request = Mock(HttpRequest)
        def headers = Mock(HttpHeaders)
        request.getHeaders() >> headers
        headersValue.entrySet().forEach({ entry ->
            headers.get(entry.getKey()) >> entry.getValue()
        })
        request
    }
}
