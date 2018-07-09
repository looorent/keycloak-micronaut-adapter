package be.looorent.micronaut.security;

import io.jsonwebtoken.Claims;

/**
 * Validates the content of a token.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
public interface TokenValidator {

    /**
     * Validates each attribute that is relevant to check in a JWT.
     * @param tokenContent a token's body
     * @throws SecurityException if a validation error occurs
     */
    void validate(Claims tokenContent) throws SecurityException;
}
