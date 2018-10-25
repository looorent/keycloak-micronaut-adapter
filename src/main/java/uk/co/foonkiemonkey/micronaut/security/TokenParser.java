package uk.co.foonkiemonkey.micronaut.security;

/**
 * Parses and validates a JWT.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
interface TokenParser {

    /**
     * @param token a textual JWT
     * @return a structured version of the token body that contains the relevant information for you app.
     * @throws SecurityException if an error occurs during the parsing
     */
    SecurityContext parse(String token) throws SecurityException;
}
