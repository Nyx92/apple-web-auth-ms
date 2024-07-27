package apple.web.authms.controller;
import apple.web.authms.dto.LoginRequestDTO;
import apple.web.authms.dto.AuthResponseDTO;
import apple.web.authms.dto.SignupRequestDTO;
import apple.web.authms.service.KeycloakService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;


// This annotation is used on a class to make it handle web requests.
// It means that whatever is returned by methods in the class is directly
// sent back to the web browser or whatever made the web request, not as HTML or a webpage, but as data (like JSON).
@RestController
// This annotation is used on a class or method to specify which URL it should respond to.
@RequestMapping("api/v1/keycloak")
public class KeycloakController {

    // Making the KeycloakService field private ensures that it is only accessible within the KeycloakController class. This is a fundamental principle of encapsulation, which helps in hiding internal implementation.
    // This makes the class easier to change and maintain because changes to the service usage do not affect other parts of the codebase.
    // Marking the KeycloakService field as final ensures that the reference to the service cannot be changed, ensuring that it is thread-safe by default. There is no risk of another thread changing the reference
    // It clearly indicates that this dependency is an essential part of the class’s state and should not be replaced.
    private final KeycloakService keycloakService;

    private static final Logger logger = LoggerFactory.getLogger(KeycloakController.class);

    // Constructor Injection. With constructor injection, you can declare your dependencies as final, which enforces immutability.
    // This means that the injected dependency cannot be changed after the object is constructed, leading to safer and more predictable code.
    // Constructor injection makes it explicit that the class cannot be instantiated without its required dependencies
    // Constructor injection makes it straightforward to create instances of your class with mock dependencies. You simply pass the mock objects to the constructor.
    @Autowired
    public KeycloakController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    // handles user login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        // The try block in Java is used for exception handling. It allows you to write code that might throw exceptions, and to handle those exceptions gracefully, rather than letting the program crash.
        try {
            AuthResponseDTO authResponse = keycloakService.authenticate(loginRequestDTO);
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    // handles user's jwt token refresh
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        try {
            String refreshToken = body.get("refreshToken");
            AuthResponseDTO authResponse = keycloakService.refreshToken(refreshToken);
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    // handles user signup
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequestDTO signupRequestDTO) {
        // The try block in Java is used for exception handling. It allows you to write code that might throw exceptions, and to handle those exceptions gracefully, rather than letting the program crash.
        try {
            AuthResponseDTO authResponse = keycloakService.signup(signupRequestDTO);
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            if (e.getMessage().contains("User exists with same email")) {
                return ResponseEntity.status(409).body("Email already exists");
            } else if (e.getMessage().contains("User exists with same username")) {
                return ResponseEntity.status(409).body("Username already exists");
            } else {
                // 500 Internal Server Error to better reflect unexpected server-side issues
                return ResponseEntity.status(500).body("Unexpected error occurred");
            }
        }
    }

    @GetMapping("/hello")
    @PreAuthorize("hasRole('client_user')")
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/hello-2")
    @PreAuthorize("hasRole('client_admin')")
    public String hello2(){
        return "Hello World for Admin";
    }
}
