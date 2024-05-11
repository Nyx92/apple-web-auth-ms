package apple.web.authms.controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// This annotation is used on a class to make it handle web requests.
// It means that whatever is returned by methods in the class is directly
// sent back to the web browser or whatever made the web request, not as HTML or a webpage, but as data (like JSON).
@RestController
// This annotation is used on a class or method to specify which URL it should respond to.
@RequestMapping("api/v1/demo")
public class KeycloakController {
    //  If you put @GetMapping("/hello") in a class with @RequestMapping("api/v1/demo"), that method will handle requests that go to "mywebsite.com/api/v1/demo/hello".
    @GetMapping
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
