package apple.web.authms.utils;

import org.springframework.security.oauth2.jwt.Jwt;
import java.util.List;
import java.util.Map;

public class JwtUtils {

    public static List<String> extractRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            Object rolesObj = realmAccess.get("roles");
            // Type Check: Before casting, check if rolesObj is an instance of List.
            // Java cannot guarantee at runtime that the object being cast is indeed a List<String>.
            // This happens because type information is erased at runtime due to Java's type erasure.
            if (rolesObj instanceof List) {
                return (List<String>) rolesObj;
            }
        }
        return List.of();
    }
}
