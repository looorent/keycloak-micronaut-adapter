package uk.co.foonkiemonkey.micronaut.security;


import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.http.hateos.JsonError;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import javax.validation.ConstraintViolationException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import com.google.gson.Gson;

import java.util.Date;
import java.util.UUID;

import static uk.co.foonkiemonkey.micronaut.security.Constant.SECURITY_CONTEXT;
import static io.micronaut.http.HttpResponse.status;
import static io.micronaut.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static io.micronaut.http.HttpStatus.UNAUTHORIZED;
import static java.util.UUID.randomUUID;

/**
 * This service is not injected as a Micronaut filter, but can be used
 * as the implementation of a Filter in the actual app.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
public class SecurityFilter implements HttpServerFilter {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityFilter.class);

    private SecurityService service;

    SecurityFilter(SecurityService service) {
        this.service = service;
    }

    /**
     * Checks the validity of a request's Authorization header and continue
     * processing the filter chain if no error occurs. Handles errors and produces a
     * 401 status if applicable.
     *
     * @param request the request that must be validated against the security checks
     * @param chain   next filters to process if no error occurs
     * @return an HTTP response whose the body is a {@link JsonError} if a Security
     *         check occurred or the result of the next filter of 'chain'.
     */
    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        return service.readAndVerifyTokenIn(request).switchMap((context -> {
            request.setAttribute(SECURITY_CONTEXT, context);
            return chain.proceed(request);
        })).onErrorReturn((exception) -> {
            if (exception instanceof SecurityException) {
                return authorizationError((SecurityException) exception);
            } else if (exception instanceof WebApplicationException) {
                return apiError((WebApplicationException) exception);
            }else if (exception instanceof ConstraintViolationException) {
                return apiError((ConstraintViolationException) exception);
            }
            else {
                return unexpectedError(exception);
            }
        });
    }

    private MutableHttpResponse<?> authorizationError(SecurityException securityException) {
        JsonError error = new JsonError(securityException.getMessage());
        return status(UNAUTHORIZED).body(error);
    }

    private MutableHttpResponse<?> apiError(WebApplicationException exception) {
        ApiError apiError = new ApiError((new Date()).getTime(), exception.getResponse().getStatus(),
                exception.getResponse().getStatusInfo().getReasonPhrase(), WebApplicationException.class.getName(),
                exception.getMessage());
        String body = new Gson().toJson(apiError);
        return HttpResponse.status(HttpStatus.valueOf(exception.getResponse().getStatus()), exception.getMessage())
                .body(body);
    }

    private MutableHttpResponse<?> apiError(ConstraintViolationException exception) {
        ApiError apiError = new ApiError((new Date()).getTime(), Response.Status.BAD_REQUEST.getStatusCode(),exception.getCause().getMessage(), ConstraintViolationException.class.getName(),
                exception.getMessage());
        String body = new Gson().toJson(apiError);
        return HttpResponse.status(HttpStatus.valueOf(Response.Status.BAD_REQUEST.getStatusCode()), exception.getMessage())
                .body(body);
    }

    private MutableHttpResponse<?> unexpectedError(Throwable error) {
        UUID errorId = randomUUID();
        LOG.error("Internal error when retrieving a parking site access: {}", errorId, error);
        String message = "An internal error occurred, please contact us by providing this ID: " + errorId;
        return status(INTERNAL_SERVER_ERROR).body(new JsonError(message));
    }
}