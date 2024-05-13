package apple.web.authms.controller;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

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
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // The JwtGrantedAuthoritiesConverter class converts Jwt to Collection<GrantedAuthority> where GrantedAuthority contains String getAuthority()
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                        extractResourceRoles(jwt).stream()
                )
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt));
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null) {
            return Set.of();
        }
        Map<String, Object> resource = (Map<String, Object>) resourceAccess.get("my-apple-web-rest-api");
        if (resource == null) {
            return Set.of();
        }
        Collection<String> resourceRoles = (Collection<String>) resource.get("roles");
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    private String getPrincipalClaimName(Jwt jwt) {
        // Check if the "preferred_username" claim is present
        if (jwt.getClaims().containsKey("preferred_username")) {
            return jwt.getClaimAsString("preferred_username");
        } else {
            return jwt.getClaimAsString("sub");  // Fallback to "sub" if "preferred_username" is not present
        }
    }
}

@Component
public class JwtAuthConverter implements Converter <Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

    private final String principleAttribute = "preferred_username";

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt source) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                        extractResourceRoles(jwt).stream()
                )
                .collect(Collectors.toSet());
        return new JwtAuthenticationToken(jwt, authorities, getPrincipleClaimName(jwt));
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (jwt.getClaim("resource_access") == null) {
            return Set.of();
        }
        resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess.get("my-apple-web-rest-api") == null) {
            return Set.of();
        }
        resource = Map<String, Object>) resourceAccess.get("my-apple-web-rest-api");
        resourceRoles = (Collection<String>)  resource.get("roles");
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    private String getPrincipleClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (principleAttribute !=null) {
            claimName = principleAttribute;
        }
        return jwt.getClaim(claimName);

    }

}