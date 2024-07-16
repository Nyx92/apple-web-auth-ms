package apple.web.authms.service;

import apple.web.authms.configuration.JwtAuthConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

// currently the Token Service is not required, as I have no idea how to change keycloak to send RS256 for email verification or
// configure a secret key for HS512
@Service
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    private final JwtDecoder rs256JwtDecoder;
    private final JwtDecoder hs512JwtDecoder;
    private final String secretKey;

    @Autowired
    public TokenService(JwtDecoder rs256JwtDecoder, JwtDecoder hs512JwtDecoder, String secretKey) {
        this.rs256JwtDecoder = rs256JwtDecoder;
        this.hs512JwtDecoder = hs512JwtDecoder;
        this.secretKey = secretKey;
    }

    public Jwt decodeRs256Jwt(String token) {
        return rs256JwtDecoder.decode(token);
    }

    public Jwt decodeHs512Jwt(String token) {
        logger.info("Secret key used for HS512 decoding: {}", secretKey);
        try {
            return hs512JwtDecoder.decode(token);
        } catch (Exception ex) {
            logger.error("Failed to decode JWT", ex);
            throw ex;
        }
    }

}
