package be.looorent.micronaut.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

import javax.inject.Singleton;
import java.security.Key;
import java.security.PublicKey;

import static be.looorent.micronaut.security.SecurityErrorType.JWT_WRONG_KID;

/**
 * This implementation of {@code SigningKeyResolver} can be used by a {@link io.jsonwebtoken.JwtParser JwtParser} to find a signing key that
 * should be used to verify a JWS signature. This implementation uses a {@link PublicKeyService} to find the public key.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
class PublicKeyResolver implements SigningKeyResolver {

    private final PublicKeyService publicKeyService;

    PublicKeyResolver(PublicKeyService publicKeyService) {
        if (publicKeyService == null) {
            throw new IllegalArgumentException("There is no implementation of PublicKeyService provided.");
        }
        this.publicKeyService = publicKeyService;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return findPublicKey(header);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return findPublicKey(header);
    }

    private PublicKey findPublicKey(JwsHeader header) {
        return this.publicKeyService
                .findPublicKey(header.getKeyId())
                .orElseThrow(() -> JWT_WRONG_KID.toException());
    }
}
