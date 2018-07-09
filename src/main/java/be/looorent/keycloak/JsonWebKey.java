package be.looorent.keycloak;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * JWK provided by Keycloak.
 * @author Lorent Lempereur - lorent.lempereur.dev@gmail.com
 */
@JsonIgnoreProperties(ignoreUnknown = true)
class JsonWebKey {

    private static final Logger LOG = LoggerFactory.getLogger(JsonWebKey.class);

    @JsonProperty("kid")
    private final String id;

    @JsonProperty("n")
    private final String modulusBase64;

    @JsonProperty("e")
    private final String exponentBase64;

    @JsonProperty("alg")
    private final String algorithm;

    @JsonProperty("kty")
    private final String type;

    @JsonProperty("use")
    private final String use;

    @JsonCreator
    public JsonWebKey(@JsonProperty("kid") String id,
                      @JsonProperty("n") String modulusBase64,
                      @JsonProperty("e") String exponentBase64,
                      @JsonProperty("alg") String algorithm,
                      @JsonProperty("kty") String type,
                      @JsonProperty("use") String use) {
        this.id = id;
        this.exponentBase64 = exponentBase64;
        this.modulusBase64 = modulusBase64;
        this.algorithm = algorithm;
        this.type = type;
        this.use = use;
    }

    public static JsonWebKey fromRSAPublicKey(String kid, RSAPublicKey key) {
        return new JsonWebKey(kid,
                key.getModulus().toString(16),
                key.getPublicExponent().toString(16),
                "RSA256",
                "RSA",
                "sig");
    }

    public String getModulusBase64() {
        return modulusBase64;
    }

    public String getExponentBase64() {
        return exponentBase64;
    }

    public String getId() {
        return id;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getType() {
        return type;
    }

    public String getUse() {
        return use;
    }

    public PublicKey toPublicKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            BigInteger modulus = new BigInteger(1, urlDecoder.decode(modulusBase64));
            BigInteger exponent = new BigInteger(1, urlDecoder.decode(exponentBase64));
            return keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException  e) {
            LOG.error("An error occurred when creating a public key from KID {}", id, e);
            return null;
        }
    }
}
