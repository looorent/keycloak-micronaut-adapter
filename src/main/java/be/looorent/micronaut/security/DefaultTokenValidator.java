package be.looorent.micronaut.security;

import io.jsonwebtoken.Claims;

import javax.inject.Singleton;

/**
 * Default implementation to validate a JWT's body. This implementation does not validate anything.
 * To override this implementation, @{@link io.micronaut.context.annotation.Replaces} must be set on
 * the replacement implementation.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
public class DefaultTokenValidator implements TokenValidator {

    @Override
    public void validate(Claims tokenContent) {
        // do nothing
    }
}
