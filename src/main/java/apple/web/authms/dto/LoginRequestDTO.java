package apple.web.authms.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
// A Data Transfer Object (DTO) is a simple Java object used to transfer data between different layers or parts of an application.
public class LoginRequestDTO {
    private String username;
    private String password;
}