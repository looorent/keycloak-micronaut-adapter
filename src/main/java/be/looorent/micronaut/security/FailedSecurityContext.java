package be.looorent.micronaut.security;

/**
 * A security context that as either failed a token validation
 * or that caught an unexpected error during this validation.
 * Wraps an exception.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
class FailedSecurityContext implements SecurityContext {

    private final Throwable exception;
    private final String message;
    private final String reason;
    private final boolean unexpected;

    public FailedSecurityContext(Throwable exception,
                                 String message,
                                 String reason,
                                 boolean unexpected) {
        this.exception = exception;
        this.message = message;
        this.reason = reason;
        this.unexpected = unexpected;
    }

    static final FailedSecurityContext unexpectedErrorDuringVerification(Throwable exception) {
        return new FailedSecurityContext(exception,
                "An unexpected error occurred during the authentication",
                "internal_error",
                true);
    }

    static final FailedSecurityContext securityErrorFound(SecurityException exception) {
        return new FailedSecurityContext(exception,
                exception.getMessage(),
                "unauthorized",
                false);
    }

    public Throwable getException() {
        return exception;
    }

    public String getMessage() {
        return message;
    }

    public String getReason() {
        return reason;
    }

    public boolean isUnexpected() {
        return unexpected;
    }
}
