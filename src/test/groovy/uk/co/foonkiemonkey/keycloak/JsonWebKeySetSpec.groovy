package uk.co.foonkiemonkey.keycloak

import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

class JsonWebKeySetSpec extends Specification {

    def "parsing a certificates works"() {
        given:
        def json = """
            {
                "keys": [
                    {
                        "kid": "4_PYYc3xAr0t7oheW31Dww6b1QneghAeV-_0Jwns6FU",
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "jMZSDVCEVVidiR-B_49g48t3OLfBPuc8eKFDo9xdQhwlcQxhXwpXSUS9Wp-RqFluZGliwSyD_xJrRyrip1KQGjfiesbg-iEc-xOWuuNhtZFU8kZPYbb5XQMHMmGPSjFAFj-QH8w2pSMF9hYt7hLiIW4UM9Bpcm_o2CjoKo9VzeQdvzOgS7ryEtTR4Vl6gWjHG5lt4ffNFmrowArD-qlSmrAmcgtFDaB75KIwk_YzXxvaXbayFnHPwApj_miISaavKDj1M8GFc27T548jJbb4A7ltOrRRPduj1ZhtWdZUj-tPixvVQYlgSTdpWIG5cx4weafMbPp5qg5C6UBPMiIX-Q",
                        "e": "AQAB"
                    }
                ]
            }
        """

        when:
        def parsedJson = new ObjectMapper().readValue(json, JsonWebKeySet)

        then:
        parsedJson != null
        parsedJson.keys != null
        parsedJson.keys.size() == 1
        parsedJson.keys.first().exponentBase64 == "AQAB"
        parsedJson.keys.first().modulusBase64 == "jMZSDVCEVVidiR-B_49g48t3OLfBPuc8eKFDo9xdQhwlcQxhXwpXSUS9Wp-RqFluZGliwSyD_xJrRyrip1KQGjfiesbg-iEc-xOWuuNhtZFU8kZPYbb5XQMHMmGPSjFAFj-QH8w2pSMF9hYt7hLiIW4UM9Bpcm_o2CjoKo9VzeQdvzOgS7ryEtTR4Vl6gWjHG5lt4ffNFmrowArD-qlSmrAmcgtFDaB75KIwk_YzXxvaXbayFnHPwApj_miISaavKDj1M8GFc27T548jJbb4A7ltOrRRPduj1ZhtWdZUj-tPixvVQYlgSTdpWIG5cx4weafMbPp5qg5C6UBPMiIX-Q"
        parsedJson.keys.first().id == "4_PYYc3xAr0t7oheW31Dww6b1QneghAeV-_0Jwns6FU"
        parsedJson.keys.first().algorithm == "RS256"
        parsedJson.keys.first().type == "RSA"
        parsedJson.keys.first().use == "sig"
    }
}
