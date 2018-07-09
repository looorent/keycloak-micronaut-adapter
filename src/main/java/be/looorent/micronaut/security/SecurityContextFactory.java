package be.looorent.micronaut.security;

import io.jsonwebtoken.Claims;

/**
 * Contract that can be implemented by the adapter's user to build their {@link SecurityContext}.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
public interface SecurityContextFactory {

    /**
     * Starting from a JWT's body, builds a context of security.
     * @param tokenContent a JWT's body; must not be null
     * @return the built security context
     */
    SecurityContext createSecurityContext(Claims tokenContent);
}
