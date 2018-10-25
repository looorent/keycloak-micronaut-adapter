package uk.co.foonkiemonkey.keycloak;


import uk.co.foonkiemonkey.micronaut.security.PublicKeyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

import static java.lang.System.currentTimeMillis;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toMap;

/**
 * Service that retrieves a set of JWK from Keycloak (using HTTP), that can eager or lazy load
 * them at initialization time.
 *
 * Requires three properties:
 * * keycloak.base-url
 * * keycloak.realm-id
 * * keycloak.eager-load-public-keys
 *
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@Singleton
@Context
public class KeycloakPublicKeyService implements PublicKeyService {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakPublicKeyService.class);

    private final URL publicCertificateUrl;
    private final boolean eagerLoadPublicKeys;
    private Map<String, PublicKey> keyPerKeycloakId;

    KeycloakPublicKeyService(
            @Value("${keycloak.base-url}") String baseUrl,
            @Value("${keycloak.realm-id}") String realmId,
            @Value("${keycloak.eager-load-public-keys}") Boolean eagerLoadPublicKeys
     ) throws MalformedURLException {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("Property keycloak.base-url (string) must be defined");
        }
        if (realmId == null || realmId.isEmpty()) {
            throw new IllegalArgumentException("Property keycloak.realm-id (string) must be defined");
        }
        if (eagerLoadPublicKeys == null) {
            throw new IllegalArgumentException("Property keycloak.eager-load-public-keys (boolean) must be defined");
        }
        this.publicCertificateUrl = createPublicCertificateUrl(baseUrl, realmId);
        this.eagerLoadPublicKeys = eagerLoadPublicKeys;
    }

    @Override
    public Optional<PublicKey> findPublicKey(String kid) {
        if (kid == null || kid.isEmpty()) {
            throw new IllegalArgumentException("kid must not be null or empty");
        }
        if (!publicKeyHasBeenLoaded()) {
            this.loadPublicKeys();
        }
        return ofNullable(keyPerKeycloakId.get(kid));
    }

    @PostConstruct
    public void initialize() {
        if (this.eagerLoadPublicKeys) {
            LOG.info("Public keys are eager loaded from Keycloak");
            this.loadPublicKeys();
        }
    }

    boolean publicKeyHasBeenLoaded() {
        return keyPerKeycloakId != null;
    }

    private synchronized void loadPublicKeys() {
        LOG.info("Retrieving public keys from keycloak at {}", publicCertificateUrl);
        long startTimeInMs = currentTimeMillis();
        keyPerKeycloakId = retrievePublicKeysFromKeycloak();
        LOG.info("Public keys retrieved in {} ms", currentTimeMillis() - startTimeInMs);
    }

    private URL createPublicCertificateUrl(String baseUrl, String realmId) throws MalformedURLException {
        String realmUrl = baseUrl + "/auth/realms/" + realmId;
        String certificateUrl = realmUrl + "/protocol/openid-connect/certs";
        return new URL(certificateUrl);
    }

    private Map<String, PublicKey> retrievePublicKeysFromKeycloak() {
        JsonWebKeySet certificates = retrieveAndParsePublicKeysFromKeycloak();
        return certificates.getKeys()
                .stream()
                .collect(toMap(
                        JsonWebKey::getId,
                        JsonWebKey::toPublicKey));
    }

    private JsonWebKeySet retrieveAndParsePublicKeysFromKeycloak() {
        try {
            return new ObjectMapper().readValue(publicCertificateUrl.openStream(), JsonWebKeySet.class);
        } catch (IOException e) {
            LOG.error("An error occurred when retrieving and unmarshalling public keys from {}", publicCertificateUrl, e);
            throw new IllegalStateException("Impossible to contact Keycloak with the properties you have provided for 'keycloak.base-url' and/or 'keycloak.realm-id'", e);
        }
    }
}
