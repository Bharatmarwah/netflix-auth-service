package in.bm.netflix_auth_service.ResponseDTO;

import lombok.*;

@Getter
@Builder
public class UserRegisterResponseDTO {

    private String message;

    private boolean emailVerificationRequired;

    private boolean mobileVerificationRequired;

}
