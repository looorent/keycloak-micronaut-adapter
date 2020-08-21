package be.looorent.micronaut.security;


import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import io.micronaut.http.hateoas.JsonError;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;

import static be.looorent.micronaut.security.Constant.SECURITY_CONTEXT;
import static io.micronaut.http.HttpResponse.status;
import static io.micronaut.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static io.micronaut.http.HttpStatus.UNAUTHORIZED;
import static io.reactivex.Flowable.fromCallable;
import static io.reactivex.schedulers.Schedulers.io;

/**
 * This service is not injected as a Micronaut filter, but can be used
 * as the implementation of a Filter in the actual app.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
public class SecurityFilter implements HttpServerFilter {

    private SecurityService service;

    SecurityFilter(SecurityService service) {
        this.service = service;
    }

    /**
     * Checks the validity of a request's Authorization header and continue processing the filter chain if no error occurs.
     * @param request the request that must be validated against the security checks
     * @param chain next filters to process if no error occurs
     * @return an HTTP response
     */
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        return service.readAndVerifyTokenIn(request).switchMap(context -> {
            if (context instanceof FailedSecurityContext) {
                return handleAuthenticationFailure((FailedSecurityContext) context);
            }
            else {
                request.setAttribute(SECURITY_CONTEXT, context);
                return chain.proceed(request);
            }
        });
    }

    private Flowable<MutableHttpResponse<JsonError>> handleAuthenticationFailure(FailedSecurityContext failure) {
        return fromCallable(() -> {
            JsonError body = new JsonError(failure.getMessage());
            HttpStatus status = failure.isUnexpected() ? INTERNAL_SERVER_ERROR : UNAUTHORIZED;
            return status(status).body(body);
        }).subscribeOn(io());
    }
}