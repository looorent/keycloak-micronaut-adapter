package uk.co.foonkiemonkey.micronaut.security;

import java.security.PublicKey;
import java.util.Optional;

/**
 * How to find a public key to validate a JWT?
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
public interface PublicKeyService {

    /**
     * This method finds a public key identified by an identifier, generally stored in a JWT header.
     * @param kid a key id
     * @return the public key identified by kid ; or return empty() is the public key has not been found.
     */
    Optional<PublicKey> findPublicKey(String kid);
}
