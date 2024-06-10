package apple.web.authms.controller;

import apple.web.authms.service.KeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VerificationController {

    @Autowired
    private KeycloakService keycloakService;

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("key") String key) {
        try {
            keycloakService.verifyEmail(key);
            return ResponseEntity.ok("Email verified successfully!");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Email verification failed.");
        }
    }
}
