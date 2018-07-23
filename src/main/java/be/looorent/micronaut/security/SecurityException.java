package be.looorent.micronaut.security;

/**
 * An a Security error occurs.
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