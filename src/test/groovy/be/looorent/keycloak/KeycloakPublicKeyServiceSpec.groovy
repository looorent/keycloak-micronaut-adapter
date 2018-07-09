package be.looorent.keycloak

import be.looorent.micronaut.security.InMemoryPublicKeyService
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

class KeycloakPublicKeyServiceSpec extends Specification {

    private static final String KEY_ID_1 = "abc"
    private static final String KEY_ID_2 = "efg"
    private static final String KEY_ID_3 = "hij"
    private static final String REALM_ID = "test"

    @Shared
    Map<String, PublicKey> keysPerId = [ "abc" : createKey(), "efg" : createKey(), "hij": createKey() ]

    @Shared
    InMemoryPublicKeyService publicKeyService = new InMemoryPublicKeyService(keysPerId)

    @AutoCleanup
    @Shared
    KeycloakServerStub server = new KeycloakServerStub(publicKeyService, REALM_ID).start()

    String baseUrl = server.baseUrl

    def "construct service with an empty baseUrl throws an exception"(String baseUrl) {
        when:
        new KeycloakPublicKeyService(baseUrl, REALM_ID, false)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "Property keycloak.base-url (string) must be defined"

        where:
        baseUrl << ["", null]
    }

    def "construct service with an empty realmId throws an exception"(String realmId) {
        when:
        new KeycloakPublicKeyService(baseUrl, realmId, false)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "Property keycloak.realm-id (string) must be defined"

        where:
        realmId << ["", null]
    }

    def "construct service with an empty eager-load-public-keys throws an exception"() {
        when:
        new KeycloakPublicKeyService(baseUrl, REALM_ID, null)

        then:
        IllegalArgumentException exception = thrown()
        exception.message == "Property keycloak.eager-load-public-keys (boolean) must be defined"
    }

    def "lazy loading waits for a call to load the keys"() {
        given: "eager loading is disabled"
        def service = new KeycloakPublicKeyService(baseUrl, REALM_ID, false)
        service.initialize()

        expect: "keys to not be loaded"
        !service.publicKeyHasBeenLoaded()

        when:
        service.findPublicKey(KEY_ID_1)

        then:
        service.publicKeyHasBeenLoaded()
    }

    def "eager loading does not wait for a call to load the keys"() {
        given: "eager loading is enabled"
        def service = new KeycloakPublicKeyService(baseUrl, REALM_ID, true)

        when:
        service.initialize()

        then:
        service.publicKeyHasBeenLoaded()
    }

    def "loading the public keys throws an exception when a wrong base url is set"() {
        given:
        def wrongUrl = baseUrl + "/wrong/"
        def service = new KeycloakPublicKeyService(wrongUrl, REALM_ID, true)

        when:
        service.initialize()

        then:
        IllegalStateException exception = thrown()
        exception.message == "Impossible to contact Keycloak with the properties you have provided for 'keycloak.base-url' and/or 'keycloak.realm-id'"
    }

    def "loading the public keys throws an exception when a wrong realm id is set"() {
        given:
        def wrongRealmId = "WRONG-${REALM_ID}"
        def service = new KeycloakPublicKeyService(baseUrl, wrongRealmId, true)

        when:
        service.initialize()

        then:
        IllegalStateException exception = thrown()
        exception.message == "Impossible to contact Keycloak with the properties you have provided for 'keycloak.base-url' and/or 'keycloak.realm-id'"
    }

    def "fetching the public keys works fine"(String id) {
        given:
        def service = new KeycloakPublicKeyService(baseUrl, REALM_ID, true)
        def key = keysPerId[id]

        when:
        def keyFound = service.findPublicKey(id)

        then:
        keyFound.isPresent()
        keyFound.get() != null
        keyFound.get() instanceof RSAPublicKey
        keyFound.get() == key

        where:
        id << [KEY_ID_1, KEY_ID_2, KEY_ID_3]
    }

    def "fetching the public keys with a wrong id throws an exception"(String wrongId) {
        given:
        def service = new KeycloakPublicKeyService(baseUrl, REALM_ID, true)

        when:
        def keyFound = service.findPublicKey(wrongId)

        then:
        !keyFound.isPresent()

        where:
        wrongId << ["Wrong-${KEY_ID_1}", "Wrong-${KEY_ID_2}"]
    }

    private PublicKey createKey() {
        def generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(1024)
        def pair = generator.generateKeyPair()
        pair.public
    }
}
