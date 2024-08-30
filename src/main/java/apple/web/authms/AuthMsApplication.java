package apple.web.authms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;


// @SpringBootApplication annotation is a combination of three annotations:
// @Configuration: Indicates that the class can be used by the Spring IoC container as a source of bean definitions.
// @EnableAutoConfiguration: Tells Spring Boot to start adding beans based on classpath settings, other beans, and various property settings.
// @ComponentScan: Tells Spring to look for other components, configurations, and services in the package,
// allowing it to find the @Configuration classes and any @Bean methods within them.
@SpringBootApplication
public class
AuthMsApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthMsApplication.class, args);
	}

}
