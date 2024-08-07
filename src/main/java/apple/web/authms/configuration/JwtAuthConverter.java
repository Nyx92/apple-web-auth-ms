package apple.web.authms.configuration;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// The JwtAuthConverter is designed to convert a Jwt object into an AbstractAuthenticationToken object. This conversion is crucial for integrating JWT-based authentication within the Spring Security framework.
// The resulting AbstractAuthenticationToken can then be used by Spring Security to make authorization decisions based on the content of the JWT.

// The Converter interface in this context comes from the Spring Framework and is a generic interface that defines a single method for converting an object of one type into another.
// AbstractAuthenticationToken is a base class for Authentication implementations that are used to store details about the currently authenticated principal.
//  This converter is now registered with Spring's formatting registry, which is part of the overall ConversionService.
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthConverter.class);

    @Value("${keycloak.resource}")
    private String keycloakClientId;

    // The JwtGrantedAuthoritiesConverter class converts Jwt to Collection<GrantedAuthority> where GrantedAuthority contains String getAuthority()
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    // Constructor to log initialization
    public JwtAuthConverter() {
        logger.info("JwtAuthConverter instantiated");
    }

    @PostConstruct
    public void postConstruct() {
        logger.info("JwtAuthConverter initialized with keycloakClientId: {}", keycloakClientId);
    }

    //  The method signature shows that it takes a Jwt object as input and returns an AbstractAuthenticationToken
    //  Basically what this does is to combine authorities in claims together, identified using jwtGrantedAuthoritiesConverter and extractResourceRoles on a single jwt
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        logger.info("JwtAuthConverter convert called with keycloakClientId: {}", keycloakClientId);

        //  It combines authorities from two sources: standard ones extracted by jwtGrantedAuthoritiesConverter (which typically reads scopes or similar claims from the JWT)
        //  and custom ones derived from our application-specific method extractResourceRoles.
        //  Stream.concat takes two streams and joins them together into one stream.
        Collection<GrantedAuthority> authorities = Stream.concat(
                        // The jwtGrantedAuthoritiesConverter extracts authorities based on standard JWT claims such as "scope" or "scp". For instance, if a JWT contains a claim like "scope": "read write",
                        // this converter would produce authorities like [SCOPE_read, SCOPE_write].
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                        // extract additional, custom authorities specific to keycloak
                        extractResourceRoles(jwt).stream()
                )
                .collect(Collectors.toSet());

        // It creates a new instance of JwtAuthenticationToken, which is a concrete implementation of AbstractAuthenticationToken, initializing it with the combined authorities and the principal's name derived from the JWT.
        return new JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt));
    }

    // extractResourceRoles extracts the roles' values from the decoded jwt token from keycloak
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        logger.info("Resource Access: {}", resourceAccess);
        if (resourceAccess == null) {
            // return empty collection
            return Set.of();
        }

        Map<String, Object> resource = (Map<String, Object>) resourceAccess.get(keycloakClientId);
        logger.info("Resource: {}", resource);
        if (resource == null) {
            return Set.of();
        }
        Collection<String> resourceRoles = (Collection<String>) resource.get("roles");
        logger.info("Resource Roles: {}", resourceRoles); // Add this line
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    // The principal name uniquely identifies the user within your system. It’s extracted from the JWT and set as part of the JwtAuthenticationToken.
    private String getPrincipalClaimName(Jwt jwt) {
        // Check if the "preferred_username" claim is present
        if (jwt.getClaims().containsKey("preferred_username")) {
            return jwt.getClaimAsString("preferred_username");
        } else {
            return jwt.getClaimAsString("sub");  // Fallback to "sub" if "preferred_username" is not present
        }
    }
}
