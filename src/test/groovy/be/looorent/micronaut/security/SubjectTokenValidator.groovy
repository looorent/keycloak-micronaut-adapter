package be.looorent.micronaut.security

import io.jsonwebtoken.Claims

import static be.looorent.micronaut.security.SecurityErrorType.VALIDATION

class SubjectTokenValidator implements TokenValidator {

    public static final String INCORRECT_SUBJECT = "incorrect subject"

    private String expectedSubject

    SubjectTokenValidator(String expectedSubject) {
        this.expectedSubject = expectedSubject
    }

    @Override
    void validate(Claims tokenContent) throws SecurityException {
        if (tokenContent.get("sub") != expectedSubject) {
            throw new SecurityException(VALIDATION, INCORRECT_SUBJECT)
        }
    }
}
