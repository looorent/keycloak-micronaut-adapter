package be.looorent.micronaut.security;

/**
 * When a known security error occurs during token parsing.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
public class SecurityException extends RuntimeException {

    private final SecurityErrorType type;

    public SecurityException(SecurityErrorType type) {
        super(type.getReason());
        this.type = type;
    }

    public SecurityException(SecurityErrorType type, String message) {
        super(message);
        this.type = type;
    }

    public SecurityErrorType getType() {
        return type;
    }
}