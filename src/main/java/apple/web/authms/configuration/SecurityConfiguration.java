package apple.web.authms.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
// Explanation of SecurityConfiguration:
// Request Filtering: When a request comes into your application, Spring Security intercepts it before it reaches any controller.
// The security filters configured in  SecurityFilterChain are applied. If the filters require a valid JWT for certain or all paths, the incoming requests must include a valid JWT in their headers.


// This tells Spring that the class is a factory method and can contain bean definitions.
@Configuration
// @EnableWebSecurity is a marker annotation that is used to enable Spring Security’s web security support and provide the Spring MVC integration.
// It essentially signals to Spring Framework to start considering the security configurations that you have set up in any WebSecurityConfigurer or more commonly, through HttpSecurity configurations.
@EnableWebSecurity
// @EnableMethodSecurity allows you to add security around methods based on annotations. It enables support for method-level security settings.
// allows you to add e.g., @PreAuthorize("hasRole('ROLE_ADMIN')") in your methods
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

    private final String keycloakIssuerUri;
    // Constructor injection for the Keycloak issuer URI
    public SecurityConfiguration(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String keycloakIssuerUri) {
        this.keycloakIssuerUri = keycloakIssuerUri;
    }

    // Indicates that the method will return an object that should be registered as a bean in the Spring application context.
    @Bean
    // http: This is the instance of HttpSecurity that you are configuring. It is used to specify how HTTP requests should be secured in your application
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Apply CSRF disabling only to specific paths
        // Disables Cross-Site Request Forgery (CSRF) protection.
        // Disabling CSRF is typical in APIs that only serve non-browser clients.
        // http.csrf(): This method obtains a CsrfConfigurer which is used to configure CSRF protection in your application
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**") // Disables CSRF for any request to /api/**
                );

        http
                // Starts a chain to specify that authorization is required for HTTP requests.
                .authorizeHttpRequests(auth -> auth
                        // Applies the subsequent rules to all requests.
                        // Specifies that all requests must be authenticated; the client must provide valid credentials.
                        .anyRequest().authenticated()
                )
                // set up how your resource server handles OAuth2 authentication
                .oauth2ResourceServer(oauth2 -> oauth2
                        // Specifies that JWT (JSON Web Token) will be used to handle authentication. I
                        .jwt(jwt -> jwt
                                // Configures a custom JwtAuthenticationConverter that converts a JWT into an Authentication object,
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                // Sets a custom JwtDecoder that is responsible for decoding and validating JWTs.
                                .decoder(jwtDecoder())
                        )
                )
                // Configures session management. It's important for REST APIs which are stateless, meaning no session state is maintained between requests.
                .sessionManagement(session -> session
                        // This setting prevents the Spring Security from creating HTTP sessions. It makes the security context rely entirely on other mechanisms (like the OAuth2 token) to authenticate each request.
                        // This is essential for making the service stateless, which is a core principle of RESTful services.
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        //  This builds and returns the configured HttpSecurity object, which is now set up to handle security according to the specified rules.
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // Specify the configuration for your JWT decoder here, often you will fetch it from application properties
            return JwtDecoders.fromOidcIssuerLocation(keycloakIssuerUri);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new JwtAuthConverter()); // Set your custom converter here
        return converter;
    }
}
