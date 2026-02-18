package in.bm.netflix_auth_service.ResponseDTO;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRefreshTokenResponse {
    private String accessToken;

}
