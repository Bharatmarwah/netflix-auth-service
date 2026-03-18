package in.bm.netflix_auth_service.CONTROLLER;

import in.bm.netflix_auth_service.RequestDTO.EmailVerificationRequestDTO;
import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRefreshTokenResponse;
import in.bm.netflix_auth_service.SERVICE.AuthUserService;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
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
    public UserRegisterResponseDTO signUp(@Valid @RequestBody
                                          UserRegisterRequestDTO userRegisterRequestDTO) {

        return authUserService.signUp(userRegisterRequestDTO);
    }

    //  login api -> post/signin (email+password or mobile+password)

    @PostMapping(value = "/login/password", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public UserLoginResponseDTO signIn(@Valid @RequestBody
                                       UserLoginRequestDTO userPasswordLoginDTO,
                                       HttpServletRequest request,
                                       HttpServletResponse response,
                                       @RequestHeader(value = "Ip-Address", required = false, defaultValue = "") String ipAddress) {

        return authUserService.signIn(userPasswordLoginDTO,request,response,ipAddress);
    }

    //  email verification api -> post/verify-email (token in body or query param)
    @PostMapping("/send-email-link")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void sendEmailVerificationOTP(@Valid @RequestBody EmailVerificationRequestDTO requestDTO){
        authUserService.sendEmailVerificationLink(requestDTO.getEmail());
    }

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    public void verifyEmail(@RequestParam("token") String token){
        authUserService.verifyEmail(token);
    }

    @PostMapping("/resend-email-link")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resendEmailVerificationLink(@Valid @RequestBody EmailVerificationRequestDTO requestDTO){
        authUserService.sendEmailVerificationLink(requestDTO.getEmail());
    }

    //  add refresh api including refresh token rotation token reuse detection
    @PostMapping("/refresh-token")
    @ResponseStatus(HttpStatus.OK)
    public UserRefreshTokenResponse refreshToken(HttpServletResponse response, HttpServletRequest request){
        return authUserService.refreshToken(response, request);
    }

    // add logout api to invalidate refresh token and clear cookies
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request ,HttpServletResponse response){
        authUserService.logout(request, response);
    }


// ================= PASSWORD MANAGEMENT =================

// TODO: Implement forgot password request
// POST /auth/user/forgot-password
// → Generate password reset token
// → Save token + expiry
// → Send reset email

// TODO: Implement reset password endpoint
// POST /auth/user/reset-password
// → Validate reset token
// → Update password (encoded)
// → Invalidate all sessions


// ================= SESSION MANAGEMENT =================

// TODO: Implement logout from all devices
// POST /auth/user/logout-all
// → Extract userId from access token
// → Revoke all user devices

// TODO: Implement change password endpoint
// POST /auth/user/change-password
// → Require valid access token
// → Validate old password
// → Update password
// → Revoke all sessions


// ================= OPTIONAL UX APIs =================

// TODO: Implement email availability check (optional)
// GET /auth/user/check-email
// → Return available: true/false
// → Avoid user enumeration leak

// TODO: Implement phone number verification via OTP (if required)
// POST /auth/user/send-otp
// POST /auth/user/verify-otp


// ================= SECURITY ENHANCEMENTS =================

// TODO: Add rate limiting for login and verification endpoints
// TODO: Add brute-force protection for login attempts
// TODO: Add device metadata tracking (IP, user-agent)
// TODO: Add audit logging for security events

}
