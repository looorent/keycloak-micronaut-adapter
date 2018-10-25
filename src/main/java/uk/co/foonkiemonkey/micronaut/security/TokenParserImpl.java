package uk.co.foonkiemonkey.micronaut.security;



/**
 * Wraps the logic to verify & parse a JWT and returns its content.
 */
import io.jsonwebtoken.*;
import io.micronaut.context.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;

import static uk.co.foonkiemonkey.micronaut.security.SecurityErrorType.*;

/**
 * Default implementation that uses jjwt to read and validate a JWT.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
class TokenParserImpl implements TokenParser {

    private static Logger LOG = LoggerFactory.getLogger(TokenParserImpl.class);

    private final TokenValidator tokenValidator;
    private final SecurityContextFactory securityContextFactory;
    private final JwtParser parser;

    TokenParserImpl(@Value("${security.token.issuer}") String tokenIssuer,
                    PublicKeyResolver publicKeyResolver,
                    SecurityContextFactory securityContextFactory,
                    TokenValidator tokenValidator) {
        if (tokenIssuer == null || tokenIssuer.isEmpty()) {
            throw new IllegalArgumentException("Property 'security.token.issuer' (string) must be set");
        }
        if (publicKeyResolver == null) {
            throw new IllegalArgumentException("No implementation of PublicKeyResolver has been found");
        }
        if (securityContextFactory == null) {
            throw new IllegalArgumentException("No implementation of SecurityContextFactory has been found");
        }
        if (tokenValidator == null) {
            throw new IllegalArgumentException("No implementation of TokenValidator has been found");
        }

        this.tokenValidator = tokenValidator;
        this.securityContextFactory = securityContextFactory;
        this.parser = Jwts.parser()
                .setSigningKeyResolver(publicKeyResolver)
                .requireIssuer(tokenIssuer);
    }

    @Override
    public SecurityContext parse(String token) throws SecurityException {
        try {
            Claims claims = parser.parseClaimsJws(token).getBody();
            tokenValidator.validate(claims);
            return securityContextFactory.createSecurityContext(claims);
        } catch (UnsupportedJwtException e) {
            throw JWT_UNSUPPORTED.toException();
        } catch (MalformedJwtException e) {
            throw JWT_MALFORMED.toException();
        } catch (SignatureException e) {
            throw JWT_WRONG_SIGNATURE.toException();
        } catch (ExpiredJwtException e) {
            throw JWT_EXPIRED.toException();
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("An error occurred when parsing a JWT", e);
            throw new SecurityException(UNKWOWN, e.getMessage());
        }
    }
}