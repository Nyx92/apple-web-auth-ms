package apple.web.authms.controller;

import apple.web.authms.dto.AuthResponseDTO;
import apple.web.authms.service.KeycloakService;
import apple.web.authms.service.TokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    @Operation(summary = "Handles email verification process")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Emailed verified",
                    content =  @Content(mediaType = "text/plain")),
            @ApiResponse(responseCode = "500", description = "Email verification failed",
                    content = @Content(mediaType = "text/plain"))
    })
    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestBody Map<String, String> body) {
        logger.info(body.toString());
        String userId = body.get("userId");
        logger.info("userId: {}", userId);
        if (userId == null || userId.isEmpty()) {
            return ResponseEntity.badRequest().body("userId is missing");
        }
        try {
            keycloakService.verifyEmailByUserId(userId);
            return ResponseEntity.ok("Email verified successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Email verification failed");
        }
    }
}
