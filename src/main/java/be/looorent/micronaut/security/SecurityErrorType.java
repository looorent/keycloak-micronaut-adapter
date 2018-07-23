package be.looorent.micronaut.security;

/**
 * Reason when a parsing error occurs on a JWS token;
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
public enum SecurityErrorType {

    /**
     * see [io.jsonwebtoken.UnsupportedJwtException]
     */
    JWT_UNSUPPORTED("jws_unsupported_by_application"),

    /**
     * [io.jsonwebtoken.MalformedJwtException]
     */
    JWT_MALFORMED("jws_malformed"),

    /**
     * [io.jsonwebtoken.ExpiredJwtException]
     */
    JWT_EXPIRED("jwt_expired"),

    /**
     * [io.jsonwebtoken.SignatureException]
     */
    JWT_WRONG_SIGNATURE("jwt_wrong_signature"),

    JWT_WRONG_KID("jwt_wrong_key_id"),

    UNKWOWN("unkwown_error"),

    /**
     * When the HTTP Authorization header is not present
     */
    AUTHORIZATION_HEADER_MISSING("authorization_header_missing"),

    /**
     * When the HTTP Authorization header does not contain a schema and a token
     */
    AUTHORIZATION_HEADER_WRONG_FORMAT("authorization_header_wrong_format"),

    /**
     * When the HTTP Authorization header does not have the "Bearer" scheme.
     */
    AUTHORIZATION_HEADER_WRONG_SCHEME("authorization_header_wrong_scheme"),

    /**
     * When a {@link TokenValidator} has rejected a token.
     */
    VALIDATION("token_content_validation");

    private final String reason;

    SecurityErrorType(String reason) {
        this.reason = reason;
    }

    public SecurityException toException() {
        return new SecurityException(this);
    }

    public String getReason() {
        return reason;
    }
}
