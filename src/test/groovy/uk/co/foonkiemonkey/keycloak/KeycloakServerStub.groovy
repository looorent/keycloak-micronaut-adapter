package uk.co.foonkiemonkey.keycloak

import uk.co.foonkiemonkey.micronaut.security.InMemoryPublicKeyService
import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpServer
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKBuilder

import static java.util.stream.Collectors.toList

class KeycloakServerStub implements AutoCloseable {

    private final InMemoryPublicKeyService publicKeyService
    private final String realmId
    private final Integer port
    private HttpServer server

    KeycloakServerStub(InMemoryPublicKeyService publicKeyService, String realmId) {
        this.publicKeyService = publicKeyService
        this.port = 9999
        this.realmId = realmId
    }

    def start() {
        server = HttpServer.create(new InetSocketAddress(port), 0).with {
            createContext(urlSuffix) { http ->
                http.responseHeaders.add("Content-type", "application/json")
                http.sendResponseHeaders(200, 0)
                http.responseBody.withWriter { out ->
                    out << new ObjectMapper().writeValueAsString(createCertificates())
                }
            }
            start()
        }
        this
    }

    def stop() {
        if (server != null) {
            server.stop(0)
        }
    }

    String getBaseUrl() {
        "http://localhost:${port}"
    }

    private String getUrlSuffix() throws MalformedURLException {
        "/auth/realms/${realmId}/protocol/openid-connect/certs"
    }

    private JSONWebKeySet createCertificates() {
        def keys = this.publicKeyService
                .keyById
                .entrySet()
                .stream()
                .map {
                    entry -> JWKBuilder.create().kid(entry.getKey()).rs256(entry.getValue())
                }.collect(toList()) as JWK[]
        def set = new JSONWebKeySet()
        set.keys = keys
        return set
    }

    @Override
    void close() throws Exception {
        stop()
    }
}
