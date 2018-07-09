package be.looorent.micronaut.security

import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.time.LocalDateTime

import static io.jsonwebtoken.SignatureAlgorithm.HS256
import static io.jsonwebtoken.SignatureAlgorithm.RS256
import static java.time.ZoneId.systemDefault

class TokenFactory {

    SignatureAlgorithm signatureAlgorithm
    LocalDateTime now
    String algorithm
    String tokenIssuer
    PublicKey publicKey
    PrivateKey privateKey
    JwtBuilder builder
    String kid
    String issuer
    String subject

    TokenFactory(String kid, String issuer, String subject) {
        algorithm = "RSA"
        now = LocalDateTime.now()
        signatureAlgorithm = RS256
        def generator = KeyPairGenerator.getInstance(algorithm)
        generator.initialize(1024)
        def pair = generator.generateKeyPair()
        publicKey = pair.public
        privateKey = pair.private
        tokenIssuer = issuer
        this.kid = kid
        this.issuer = issuer
        this.subject = subject
        builder = Jwts.builder()
            .setIssuedAt(nowAsDate)
            .setSubject(subject)
            .setHeaderParam("kid", kid)
            .setIssuer(issuer)
            .setExpiration(validExpirationDate)
            .signWith(signatureAlgorithm, privateKey)

    }

    String createValidToken() {
        builder.compact()
    }

    Date getValidExpirationDate() {
        def tomorrow = now.plusDays(1)
        Date.from(tomorrow.atZone(systemDefault()).toInstant())
    }

    Date getLastMonth() {
        def lastMonth = now.minusMonths(1)
        Date.from(lastMonth.atZone(systemDefault()).toInstant())
    }

    Date getLastWeek() {
        def lastWeek = now.minusWeeks(1)
        Date.from(lastWeek.atZone(systemDefault()).toInstant())
    }

    Date getNowAsDate() {
        Date.from(now.atZone(systemDefault()).toInstant())
    }

    String createTokenWithoutSignature() {
        Jwts.builder()
                .setIssuedAt(nowAsDate)
                .setSubject(subject)
                .setHeaderParam("kid", kid)
                .setIssuer(issuer)
                .setExpiration(validExpirationDate).compact()
    }

    String createMalformedToken() {
        "abcd"
    }

    String createTokenWronglySigned(PrivateKey privateKey) {
        builder.signWith(RS256, privateKey).compact()
    }

    String createExpiredToken() {
        builder.setIssuedAt(lastMonth).setExpiration(lastWeek).compact()
    }

    String createTokenWithOtherSubject() {
        builder.setSubject("wrong-subject").compact()
    }


}
