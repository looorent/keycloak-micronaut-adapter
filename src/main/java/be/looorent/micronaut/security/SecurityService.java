package be.looorent.micronaut.security;

import io.micronaut.http.HttpRequest;
import io.reactivex.Flowable;

import javax.inject.Singleton;

import static be.looorent.micronaut.security.FailedSecurityContext.securityErrorFound;
import static be.looorent.micronaut.security.FailedSecurityContext.unexpectedErrorDuringVerification;
import static be.looorent.micronaut.security.SecurityErrorType.*;
import static io.reactivex.Flowable.fromCallable;
import static io.reactivex.schedulers.Schedulers.io;

/**
 * This service reads the Authorization header in an HTTP requests to validates its content.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
class SecurityService {

    private static final String HEADER_NAME = "Authorization";
    private static final String BEARER_SCHEME = "Bearer";

    private TokenParser tokenParser;

    SecurityService(TokenParser tokenParser) {
        if (tokenParser == null) {
            throw new IllegalArgumentException("No implementation of TokenParser has been found");
        }
        this.tokenParser = tokenParser;
    }

    Flowable<SecurityContext> readAndVerifyTokenIn(HttpRequest<?> request)  {
        return fromCallable(() -> {
            try {
                String token = readTokenInHeadersOf(request);
                return tokenParser.parse(token);
            }
            catch (SecurityException e) {
                return securityErrorFound(e);
            }
            catch (Throwable e) {
                return unexpectedErrorDuringVerification(e);
            }
        }).subscribeOn(io());
    }

    private String readTokenInHeadersOf(HttpRequest<?> request) throws SecurityException {
        String authorizationHeader = request.getHeaders().get(HEADER_NAME);
        if (authorizationHeader == null) {
            throw AUTHORIZATION_HEADER_MISSING.toException();
        }

        String[] schemeAndToken = authorizationHeader.split(" ");
        if (schemeAndToken.length != 2) {
            throw AUTHORIZATION_HEADER_WRONG_FORMAT.toException();
        }

        if (!BEARER_SCHEME.equalsIgnoreCase(schemeAndToken[0])) {
            throw AUTHORIZATION_HEADER_WRONG_SCHEME.toException();
        }
        return schemeAndToken[1];
    }
}