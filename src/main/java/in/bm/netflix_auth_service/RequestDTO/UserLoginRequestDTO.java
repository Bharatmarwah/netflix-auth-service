package in.bm.netflix_auth_service.RequestDTO;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserLoginRequestDTO {

    private String email;

    private String mobileNumber;

    @NotBlank
    private String password;

}
