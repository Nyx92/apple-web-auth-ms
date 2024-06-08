package apple.web.authms.service;

import apple.web.authms.configuration.JwtAuthConverter;
import apple.web.authms.dto.AuthResponseDTO;
import apple.web.authms.dto.LoginRequestDTO;
import apple.web.authms.dto.SignupRequestDTO;
import apple.web.authms.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

@Service
public class KeycloakService {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakService.class);

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${keycloak.resource}")
    private String keycloakClientId;

    @Value("${keycloak.admin-username}")
    private String keycloakAdminUsername;

    @Value("${keycloak.admin-password}")
    private String keycloakAdminPassword;

    private final JwtDecoder jwtDecoder;
    private final JwtAuthConverter jwtAuthConverter;

    public KeycloakService(JwtDecoder jwtDecoder, JwtAuthConverter jwtAuthConverter) {
        this.jwtDecoder = jwtDecoder;
        this.jwtAuthConverter = jwtAuthConverter;
    }

    // Get admin access token method for sign up service
    private String getAdminAccessToken() throws Exception {
        logger.info("Requesting admin access token from Keycloak");

        RestTemplate restTemplate = new RestTemplate();
        String authUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", keycloakClientId);
        map.add("username", keycloakAdminUsername);
        map.add("password", keycloakAdminPassword);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {});

        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("access_token")) {
                logger.debug("Admin access token received successfully");
                return (String) responseBody.get("access_token");
            } else {
                logger.error("Invalid response from authentication server: {}", responseBody);
                throw new Exception("Invalid response from authentication server");
            }
        } else {
            logger.error("Failed to obtain admin access token. Status: {}, Response: {}", response.getStatusCode(), response);
            throw new Exception("Invalid credentials");
        }
    }


    // this method authenticates a user
    public AuthResponseDTO authenticate(LoginRequestDTO loginRequest) throws Exception {
        logger.info("Starting authentication process for username: {}", loginRequest.getUsername());

        // RestTemplate is a synchronous client provided by the Spring Framework for making HTTP requests.
        RestTemplate restTemplate = new RestTemplate();
        // Prepare the URL
        String authUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // Prepare the Request Body
        // The OAuth 2.0 specification, which Keycloak follows for token requests, defines that the data should be sent as application/x-www-form-urlencoded.
        // MultiValueMap is used here because it conveniently maps to the application/x-www-form-urlencoded format.
        // MultiValueMap is used when dealing with form submissions (such as application/x-www-form-urlencoded content type), because it's common to use a data structure that can handle multiple values for a single key.
        // This is because HTML forms can have multiple input fields with the same name. It is a common practice in Spring applications to use MultiValueMap for request parameters, headers, and form data, ensuring consistency across the codebase.
        // Example of form-encoded data for OAuth 2.0 token request: grant_type=password&client_id=my-client&username=johndoe&password=secret
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", keycloakClientId);
        map.add("username", loginRequest.getUsername());
        map.add("password", loginRequest.getPassword());
        // Create HttpEntity, this wraps the headers and body in an HttpEntity object.
        // A MultiValueMap is a special type of map that can hold multiple values for a single key. MultiValueMap is useful when you need to store multiple values for a key,
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        // Make the HTTP Request:
        // new ParameterizedTypeReference<Map<String, Object>>() {}: captures the generic type information at runtime, allowing RestTemplate to correctly deserialize the response.
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {});

        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("access_token")) {
                // token would be the jwt token received from keycloak on auth success
                String token = (String) responseBody.get("access_token");
                // refresh token is received from keycloak on auth success
                String refreshToken = (String) responseBody.get("refresh_token");
                logger.info("Authentication successful for username: {}", loginRequest.getUsername());
                // return the token along with the decoded user details to the frontend on login
                return new AuthResponseDTO(token, refreshToken);
            } else {
                logger.error("Invalid response from authentication server: {}", responseBody);
                throw new Exception("Invalid response from authentication server");
            }
        } else {
            logger.error("Authentication failed for username: {}. Status: {}, Response: {}", loginRequest.getUsername(), response.getStatusCode(), response);
            throw new Exception("Invalid credentials");
        }
    }

    // this method sends a refresh token and authenticates a user
    public AuthResponseDTO refreshToken(String refreshToken) throws Exception {
        logger.info("Starting refresh token process");

        RestTemplate restTemplate = new RestTemplate();
        String authUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "refresh_token");
        map.add("client_id", keycloakClientId);
        map.add("refresh_token", refreshToken);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {});

        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("access_token")) {
                String token = (String) responseBody.get("access_token");
                String newRefreshToken = (String) responseBody.get("refresh_token");
                logger.info("Refresh token successful");
                return new AuthResponseDTO(token, newRefreshToken);
            } else {
                logger.error("Invalid response from authentication server: {}", responseBody);
                throw new Exception("Invalid response from authentication server");
            }
        } else {
            logger.error("Refresh token failed. Status: {}, Response: {}", response.getStatusCode(), response);
            throw new Exception("Invalid refresh token");
        }
    }

    // this method is used when a user signs up - help me edit this
    public AuthResponseDTO signup(SignupRequestDTO userSignUpDetails) throws Exception {
        logger.info("Starting user signup process for email: {}", userSignUpDetails.getEmail());

        // get the admin access token via the method above
        String adminAccessToken = getAdminAccessToken();
        RestTemplate restTemplate = new RestTemplate();
        String createUserUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminAccessToken);

        Map<String, Object> user = new HashMap<>();
        user.put("username", userSignUpDetails.getEmail());
        // An enabled user in keycloask can authenticate and access the services, while a disabled user cannot log in.
        user.put("enabled", true);
        user.put("firstName", userSignUpDetails.getFirstName());
        user.put("lastName", userSignUpDetails.getLastName());
        user.put("email", userSignUpDetails.getEmail());
        user.put("attributes", Map.of("phoneNumber", userSignUpDetails.getPhoneNumber(), "country", userSignUpDetails.getCountry(), "dateOfBirth", userSignUpDetails.getDateOfBirth()));

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);
        ResponseEntity<String> response = restTemplate.exchange(createUserUrl, HttpMethod.POST, request, String.class);

        if (response.getStatusCode() == HttpStatus.CREATED) {
            logger.info("User created successfully in Keycloak for email: {}", userSignUpDetails.getEmail());
            // Get the created user's ID
            String userId = response.getHeaders().getLocation().getPath().split("/")[response.getHeaders().getLocation().getPath().split("/").length - 1];

            // Set the user's password
            String setPasswordUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users/" + userId + "/reset-password";

            Map<String, String> password = new HashMap<>();
            password.put("type", "password");
            password.put("value", userSignUpDetails.getPassword());
            password.put("temporary", "false");

            HttpEntity<Map<String, String>> passwordRequest = new HttpEntity<>(password, headers);
            restTemplate.exchange(setPasswordUrl, HttpMethod.PUT, passwordRequest, String.class);

            return new AuthResponseDTO("User created successfully", null);
        } else {
            logger.error("User creation failed in Keycloak for email: {}. Status: {}, Response: {}", userSignUpDetails.getEmail(), response.getStatusCode(), response);
            throw new Exception("User creation failed");
        }
    }
}
