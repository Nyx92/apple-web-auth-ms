package apple.web.authms.service;

import apple.web.authms.configuration.JwtAuthConverter;
import apple.web.authms.dto.AuthResponseDTO;
import apple.web.authms.dto.LoginRequestDTO;
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

import java.util.List;
import java.util.Map;

@Service
public class KeycloakService {

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${keycloak.resource}")
    private String keycloakClientId;

    @Value("${keycloak.credentials.secret}")
    private String keycloakClientSecret;

    private final JwtDecoder jwtDecoder;
    private final JwtAuthConverter jwtAuthConverter;

    public KeycloakService(JwtDecoder jwtDecoder, JwtAuthConverter jwtAuthConverter) {
        this.jwtDecoder = jwtDecoder;
        this.jwtAuthConverter = jwtAuthConverter;
    }

    public AuthResponseDTO authenticate(LoginRequestDTO loginRequest) throws Exception {
        // RestTemplate is a synchronous client provided by the Spring Framework for making HTTP requests.
        RestTemplate restTemplate = new RestTemplate();
        // Prepare the URL
        String authUrl = keycloakAuthServerUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token";
        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // Prepare the Request Body
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("client_id", keycloakClientId);
        map.add("client_secret", keycloakClientSecret);
        map.add("username", loginRequest.getUsername());
        map.add("password", loginRequest.getPassword());
        // Create HttpEntity, this wraps the headers and body in an HttpEntity object.
        // A MultiValueMap is a special type of map that can hold multiple values for a single key. MultiValueMap is useful when you need to store multiple values for a key,
        // such as when constructing HTTP request parameters or headers. MultiValueMap<String, String>: Declares a map where each key is a String and each key can have multiple String values.
        // MultiValueMap is used when dealing with form submissions (such as application/x-www-form-urlencoded content type), because it's common to use a data structure that can handle multiple values for a single key.
        // This is because HTML forms can have multiple input fields with the same name. It is a common practice in Spring applications to use MultiValueMap for request parameters, headers, and form data, ensuring consistency across the codebase.
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        // Make the HTTP Request:
        // new ParameterizedTypeReference<Map<String, Object>>() {}: captures the generic type information at runtime, allowing RestTemplate to correctly deserialize the response.
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(authUrl, HttpMethod.POST, request, new ParameterizedTypeReference<Map<String, Object>>() {});

        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("access_token")) {
                // token would be the jwt token received from keycloak on auth success
                String token = (String) responseBody.get("access_token");
                // decode the jwt token to get keycloak's fields
                Jwt jwt = jwtDecoder.decode(token);
                String userId = jwt.getSubject();
                String username = jwt.getClaimAsString("preferred_username");
                String email = jwt.getClaimAsString("email");
                // Extract roles using utility method
                //  the roles in the realm_access claim are nested inside a map. This is why you need to extract the realm_access claim as a map and then navigate to the roles.
                List<String> roles = JwtUtils.extractRoles(jwt);

                return new AuthResponseDTO(token, userId, username, email, roles);
            } else {
                throw new Exception("Invalid response from authentication server");
            }
        } else {
            throw new Exception("Invalid credentials");
        }
    }
}
