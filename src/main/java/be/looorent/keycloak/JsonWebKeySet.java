package be.looorent.keycloak;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Set of JWK provided by Keycloak.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
class JsonWebKeySet {

    @JsonProperty("keys")
    private final List<JsonWebKey> keys;

    @JsonCreator
    public JsonWebKeySet(@JsonProperty("keys") List<JsonWebKey> keys) {
        this.keys = keys;
    }

    public List<JsonWebKey> getKeys() {
        return keys;
    }
}
