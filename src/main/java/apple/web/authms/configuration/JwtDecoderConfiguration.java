package apple.web.authms.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// JwtDecoder: This is set up to decode the JWT. It checks the JWT’s signature and parses the JWT to extract claims.
// The JwtDecoder you configure is responsible for ensuring the JWT is valid and trustworthy,
// typically by validating the signature against a key set obtained from the issuer's well-known configuration URL.
@Configuration
public class JwtDecoderConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(JwtDecoderConfiguration.class);

    private final String keycloakIssuerUri;

    private final String secretKey;

    // Constructor injection for the Keycloak issuer URI
    // Benefits: Immutability - fields may be final
    // Ease of Testing: easily mock or provide different values for testing
    public JwtDecoderConfiguration(
            @Value("${keycloak.auth-server-url}") String keycloakAuthServerUrl,
            @Value("${keycloak.realm}") String keycloakRealm,
            @Value("${jwt.secret-key}") String secretKey

    ) {
        this.keycloakIssuerUri =  keycloakAuthServerUrl + "/realms/" + keycloakRealm;
        this.secretKey =  secretKey;
    }

    @Bean
    @Primary
    public JwtDecoder rs256JwtDecoder() {
        return JwtDecoders.fromOidcIssuerLocation(keycloakIssuerUri);
    }

    @Bean
    public JwtDecoder hs512JwtDecoder() {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA512");
        logger.info("Using secret key for HS512 decoding: {}", secretKey);
        return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS512).build();
    }

    @Bean
    public String secretKey() {
        return secretKey;
    }
}

