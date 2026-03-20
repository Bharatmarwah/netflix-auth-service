package in.bm.netflix_auth_service.RequestDTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class OtpRequestDTO {

    @Pattern(regexp = "^[0-9]{10}$",message = "Invalid mobile number")
    private String mobileNumber;

    @NotBlank
    private String otp;
}
