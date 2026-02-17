package in.bm.netflix_auth_service.CONTROLLER;


import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.SERVICE.AuthUserService;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/user")
@RequiredArgsConstructor
public class AuthUserController {

    private final AuthUserService authUserService;

    //  register api -> post/signup

    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public UserRegisterResponseDTO signUp(@RequestBody
                                          UserRegisterRequestDTO userRegisterRequestDTO) {

        return authUserService.signUp(userRegisterRequestDTO);
    }

    //  login api -> post/signin (email+password or mobile+password)

    @PostMapping(value = "/login/password", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public UserLoginResponseDTO signIn(@RequestBody
                                       UserLoginRequestDTO userPasswordLoginDTO,
                                       HttpServletResponse response,
                                       @RequestHeader(value = "Ip-Address", required = false, defaultValue = "") String ipAddress) {

        return authUserService.signIn(userPasswordLoginDTO, response, ipAddress);
    }

    // add device tracking for user login trustification

    // todo: add refresh api including refresh token rotation token reuse detection

    // POST /refresh-token
    //
    //1. Get refresh token from HttpOnly cookie
    //2. Get deviceId from cookie
    //3. Find device session
    //4. Check:
    //   - isRevoked = false
    //   - expiresAt > now
    //   - hash matches
    //5. If valid →
    //      generate new access token
    //      generate new refresh token
    //      replace hash in DB
    //      send new refresh token cookie
    //6. If hash mismatch but session exists →
    //      reuse detected →
    //      revoke all sessions
    //      return 401

    // todo send verification email and sms for email and mobile verification with separate endpoints for verification and resend verification





}
