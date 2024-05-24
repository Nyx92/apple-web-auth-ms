package apple.web.authms.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfiguration implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // "/**" is a pattern that matches all endpoints in your Spring Boot application.*/
        // This means the CORS configuration applied here will be valid for all HTTP endpoints (e.g., /api/v1/keycloak/login, /api/v1/keycloak/hello, etc.).
        registry.addMapping("/**")
                // This specifies which origins are allowed to access the resources of your application.
                .allowedOrigins("http://localhost:5173", "https://your-production-domain.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}

