package in.bm.netflix_auth_service.CONTROLLER;


import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.SERVICE.AuthUserService;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/user")
@RequiredArgsConstructor
public class AuthUserController {

    private final AuthUserService authUserService;

    // todo : register api -> post/signup

    @PostMapping(value = "/register",produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public UserRegisterResponseDTO signUp(@RequestBody
                                              UserRegisterRequestDTO userRegisterRequestDTO)
    {
        return authUserService.signUp(userRegisterRequestDTO);
    }

    // todo: login api -> post/signin (email+password or mobile+password)

    @PostMapping(value = "/login/password",produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public UserLoginResponseDTO signIn(@RequestBody
                                           UserLoginRequestDTO userPasswordLoginDTO){

        return authUserService.signIn(userPasswordLoginDTO);
    }

    // todo: add device tracking for user login trustification


}
