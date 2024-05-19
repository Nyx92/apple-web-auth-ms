package apple.web.authms.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

// Parameterized constructor for concise initialization
// Ensures that all necessary fields are initialized when the object is created.
// Setters: Does not enforce that all fields are set, potentially leading to partially initialized objects if some setters are not called.
@AllArgsConstructor
@Getter
@Setter
public class AuthResponseDTO {
    private String token;
    private String userId;
    private String username;
    private String email;
    private List<String> roles;
}
