package in.bm.netflix_auth_service.ResponseDTO;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserLoginResponseDTO {

    private String userId;
    private String role;
    private String accessToken;
    private String tokenType;

}
