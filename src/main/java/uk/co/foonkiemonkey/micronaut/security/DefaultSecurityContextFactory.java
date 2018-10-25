package uk.co.foonkiemonkey.micronaut.security;

import io.jsonwebtoken.Claims;

import javax.inject.Singleton;

/**
 * Default implementation to create an empty {@link SecurityContext}.
 * To override this implementation, @{@link io.micronaut.context.annotation.Replaces} must be set on
 * the replacement implementation.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
public class DefaultSecurityContextFactory implements SecurityContextFactory {
    @Override
    public SecurityContext createSecurityContext(Claims tokenContent) {
        return new SecurityContext() {};
    }
}
