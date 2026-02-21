package in.bm.netflix_auth_service.CONTROLLER;

import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRefreshTokenResponse;
import in.bm.netflix_auth_service.SERVICE.AuthUserService;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
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
                                       HttpServletRequest request,
                                       HttpServletResponse response,
                                       @RequestHeader(value = "Ip-Address", required = false, defaultValue = "") String ipAddress) {

        return authUserService.signIn(userPasswordLoginDTO,request,response,ipAddress);
    }

    // add device tracking for user login trustification

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
    
    // ================= AUTH TODOs =================

// TODO: Implement email verification flow
// POST /auth/user/send-verification
// → Generate verification token
// → Save token + expiry
// → Send email with verification link

// TODO: Implement email verification confirmation
// POST /auth/user/verify-email
// → Accept token
// → Validate token + expiry
// → Mark emailVerified = true

// TODO: Implement resend verification endpoint
// POST /auth/user/resend-verification
// → Regenerate token if not verified
// → Send email again
// → Return generic response (prevent enumeration)


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
