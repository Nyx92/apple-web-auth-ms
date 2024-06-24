package apple.web.authms.controller;

import apple.web.authms.service.KeycloakService;
import apple.web.authms.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

@RestController
@RequestMapping("api/v1/keycloak")
public class VerificationController {

    @Autowired
    private KeycloakService keycloakService;

    @Autowired
    private TokenService tokenService;

    // This method creates a logger instance associated with the specified class. This association helps in organizing logs by class
    // and is useful when debugging issues specific to certain parts of the application.
    private static final Logger logger = LoggerFactory.getLogger(VerificationController.class);

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestBody Map<String, String> body) {
        String key = body.get("key");
        logger.info("key: {}", key);
        if (key == null || key.isEmpty()) {
            return ResponseEntity.badRequest().body("Key is missing");
        }
        try {
            logger.info("Trying to decode");
            // Decode the JWT to extract the user ID
            Jwt decodedJwt = tokenService.decodeHs512Jwt(key);

            logger.info("Decoded JWT: {}", decodedJwt);
            String userId = decodedJwt.getClaimAsString("sub");


            keycloakService.verifyEmailByUserId(userId);
            return ResponseEntity.ok("Email verified successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Email verification failed");
        }
    }
}
