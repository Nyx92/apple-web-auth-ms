package apple.web.authms.service;

import apple.web.authms.dto.AuthResponseDTO;
import apple.web.authms.dto.LoginRequestDTO;
import apple.web.authms.dto.SignupRequestDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    // this method gets admin access token method for sign up service
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
        ResponseEntity<Map<String, Object>> response;
        // Make the HTTP Request:
        try {
            response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {
            });
            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null && responseBody.containsKey("access_token")) {
                    logger.info("Admin access token received successfully {}", responseBody.get("access_token"));
                    return (String) responseBody.get("access_token");
                } else {
                    logger.error("Invalid response from authentication server: {}", responseBody);
                    throw new Exception("Invalid response from authentication server");
                }
            } else {
                logger.error("Failed to obtain admin access token. Status: {}, Response: {}", response.getStatusCode(), response);
                throw new Exception("Invalid credentials");
            }
        } catch (Exception e) {
            logger.error("Exception occurred while requesting admin access token: {}", e.getMessage(), e);
            throw e;
        }
    }

    // this method to send verification email
    private void sendVerificationEmail(String userId, String adminAccessToken) throws Exception {
        logger.info("Sending verification email for user ID: {}", userId);

        RestTemplate restTemplate = new RestTemplate();
        String verifyEmailUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users/" + userId + "/send-verify-email";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminAccessToken);

        HttpEntity<?> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(verifyEmailUrl, HttpMethod.PUT, request, String.class);
            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                logger.info("Verification email sent successfully for user ID: {}", userId);
            } else {
                logger.error("Failed to send verification email. Status: {}, Response: {}", response.getStatusCode(), response);
                throw new Exception("Failed to send verification email");
            }
        } catch (Exception e) {
            logger.error("Exception occurred while sending verification email: {}", e.getMessage(), e);
            throw e;
        }
    }

    // this method verifies user's email through user id
    public void verifyEmailByUserId(String userId) throws Exception {
        logger.info("Verifying user's email with id: {}", userId);

        String adminAccessToken = getAdminAccessToken();
        RestTemplate restTemplate = new RestTemplate();
        String userUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users/" + userId;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminAccessToken);

        Map<String, Object> updates = new HashMap<>();
        updates.put("emailVerified", true);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(updates, headers);

        try {
            restTemplate.exchange(userUrl, HttpMethod.PUT, request, Void.class);
            logger.info("Email verified successfully for user: {}", userId);
        } catch (Exception e) {
            logger.error("Exception occurred while verifying email via admin API: {}", e.getMessage(), e);
            throw e;
        }
    }

    // this method authenticates a user when they log in into the app using a username and password
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
        ResponseEntity<Map<String, Object>> response;
        // Make the HTTP Request:
        try {
            // new ParameterizedTypeReference<Map<String, Object>>() {}: captures the generic type information at runtime, allowing RestTemplate to correctly deserialize the response.
            response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {
            });
            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null && responseBody.containsKey("access_token")) {
                    // token would be the jwt token received from keycloak on auth success
                    String token = (String) responseBody.get("access_token");
                    // refresh token is received from keycloak on auth success
                    String refreshToken = (String) responseBody.get("refresh_token");
                    logger.info("Authentication successful for username: {}", loginRequest.getUsername());
                    // return the token along with the decoded user details to the frontend on login
                    return new AuthResponseDTO(token, refreshToken, "login successful");
                }
            }
        } catch (HttpClientErrorException.Unauthorized e) {
            // Handle 401 Unauthorized separately
            logger.error("Invalid credentials for username: {}", loginRequest.getUsername());
            throw new Exception("Invalid credentials provided", e);
        } catch (HttpClientErrorException e) {
            // Handle other HTTP errors
            logger.error("HTTP error during authentication for username: {}. Status: {}", loginRequest.getUsername(), e.getStatusCode());
            throw new Exception("Authentication failed due to HTTP error", e);
        } catch (Exception e) {
            // Handle non-HTTP errors (e.g., network issues, unexpected server response)
            logger.error("Unexpected error during authentication for username: {}", loginRequest.getUsername(), e);
            throw new Exception("Authentication failed due to unexpected error", e);
        }
        // We should never reach this point
        throw new IllegalStateException("Unexpected error during authentication");
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

        ResponseEntity<Map<String, Object>> response;
        // Make the HTTP Request:
        try {
            response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {
            });
            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null && responseBody.containsKey("access_token")) {
                    String token = (String) responseBody.get("access_token");
                    String newRefreshToken = (String) responseBody.get("refresh_token");
                    logger.info("Refresh token successful");
                    return new AuthResponseDTO(token, newRefreshToken, "refresh token successful");
                } else {
                    logger.error("Invalid response from authentication server: {}", responseBody);
                    throw new Exception("Invalid response from authentication server");
                }
            } else {
                logger.error("Refresh token failed. Status: {}, Response: {}", response.getStatusCode(), response);
                throw new Exception("Invalid refresh token");
            }
        } catch (Exception e) {
            logger.error("Exception occurred while refreshing user's token in Keycloak: {}", e.getMessage(), e);
            throw e;
        }
    }

    // this method is to signup a user
    public AuthResponseDTO signup(SignupRequestDTO userSignUpDetails) throws Exception {
        logger.info("Starting user signup process for email: {}", userSignUpDetails.getEmail());

        String adminAccessToken = getAdminAccessToken();
        RestTemplate restTemplate = new RestTemplate();
        String createUserUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminAccessToken);

        Map<String, Object> user = new HashMap<>();
        user.put("username", userSignUpDetails.getUsername());
        user.put("enabled", true);
        user.put("firstName", userSignUpDetails.getFirstName());
        user.put("lastName", userSignUpDetails.getLastName());
        user.put("email", userSignUpDetails.getEmail());
        user.put("attributes", Map.of(
                "phoneNumber", userSignUpDetails.getPhoneNumber(),
                "countryCode", userSignUpDetails.getCountryCode(),
                "country", userSignUpDetails.getCountry(),
                "dateOfBirth", userSignUpDetails.getDateOfBirth()
        ));

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);
        ResponseEntity<String> response;
        // Make the HTTP Request:
        try {
            logger.info("Sending request to Keycloak: URL={}, Request={}", createUserUrl, request);
            // RestTemplate is a synchronous client for performing HTTP requests, provided by the Spring Framework.
            // The exchange method is versatile and can be used for making various types of HTTP requests (GET, POST, PUT, DELETE, etc.).
            response = restTemplate.exchange(createUserUrl, HttpMethod.POST, request, String.class);
            logger.info("Response received from Keycloak: Status={}, Body={}", response.getStatusCode(), response.getBody());
            if (response.getStatusCode() == HttpStatus.CREATED) {
                logger.info("User created successfully in Keycloak for username: {}", userSignUpDetails.getUsername());
                String userId = response.getHeaders().getLocation().getPath().split("/")[response.getHeaders().getLocation().getPath().split("/").length - 1];
                String setPasswordUrl = keycloakAuthServerUrl + "/admin/realms/" + keycloakRealm + "/users/" + userId + "/reset-password";
                Map<String, String> password = new HashMap<>();
                password.put("type", "password");
                password.put("value", userSignUpDetails.getPassword());
                password.put("temporary", "false");
                HttpEntity<Map<String, String>> passwordRequest = new HttpEntity<>(password, headers);
                restTemplate.exchange(setPasswordUrl, HttpMethod.PUT, passwordRequest, String.class);

                // Send verification email
                sendVerificationEmail(userId, adminAccessToken);
                return new AuthResponseDTO(null, null,"User created successfully");
            }
            // This is a specific subclass of RestClientResponseException used in Spring's RestTemplate to represent HTTP 4xx client errors.
            // It provides more context about the HTTP status code and the response body, making it easier to handle specific HTTP errors (e.g., 404 Not Found, 409 Conflict).
        } catch (HttpClientErrorException e) {
            logger.error("Exception occurred while creating user account {} in Keycloak: {}", userSignUpDetails.getEmail(), e.getMessage(), e);
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                if (e.getResponseBodyAsString().contains("User exists with same email")) {
                    throw new Exception("User exists with same email");
                } else if (e.getResponseBodyAsString().contains("User exists with same username")) {
                    throw new Exception("User exists with same username");
                }
            }
        }
        // Add a final catch-all error statement if the user creation is not successful
        throw new Exception("User creation failed due to an unexpected error");
        }
}

