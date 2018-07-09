package be.looorent.micronaut.security

import java.security.PublicKey

import static java.util.Optional.ofNullable

class InMemoryPublicKeyService implements PublicKeyService {

    final Map<String, PublicKey> keyById

    InMemoryPublicKeyService() {
        this.keyById = new HashMap<>()
    }

    InMemoryPublicKeyService(Map<String, PublicKey> keyById) {
        this()
        keyById.entrySet().each { entry -> this.keyById.put(entry.key, entry.value) }
    }

    @Override
    Optional<PublicKey> findPublicKey(String kid) {
        return ofNullable(keyById[kid])
    }

    def addKey(String id, PublicKey key) {
        this.keyById.put(id, key)
    }
}
