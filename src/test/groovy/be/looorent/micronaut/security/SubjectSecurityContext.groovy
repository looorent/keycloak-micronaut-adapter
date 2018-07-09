package be.looorent.micronaut.security

import groovy.transform.EqualsAndHashCode

@EqualsAndHashCode(includes = ["subject"])
class SubjectSecurityContext implements SecurityContext {

    String subject

    SubjectSecurityContext(String subject) {
        this.subject = subject
    }
}
