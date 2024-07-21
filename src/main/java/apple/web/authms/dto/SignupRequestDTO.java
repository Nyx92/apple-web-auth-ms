package apple.web.authms.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequestDTO {
    private String firstName;
    private String lastName;
    private String country;
    private String dateOfBirth;
    private String username;
    private String email;
    private int phoneNumber;
    private int countryCode;
    private String password;
}
