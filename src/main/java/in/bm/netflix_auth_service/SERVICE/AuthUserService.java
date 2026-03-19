package in.bm.netflix_auth_service.SERVICE;

import in.bm.netflix_auth_service.ENTITY.*;
import in.bm.netflix_auth_service.EXCEPTION.InvalidCredentialsException;
import in.bm.netflix_auth_service.EXCEPTION.UserAlreadyExistException;
import in.bm.netflix_auth_service.EXCEPTION.UserNotFound;
import in.bm.netflix_auth_service.REPOSITORY.AuthUserRepository;
import in.bm.netflix_auth_service.REPOSITORY.UserDeviceRepository;
import in.bm.netflix_auth_service.REPOSITORY.VerificationOtpRepository;
import in.bm.netflix_auth_service.REPOSITORY.VerificationTokenRepository;
import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRefreshTokenResponse;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.apache.commons.validator.routines.EmailValidator;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthUserService {

    private final AuthUserRepository authUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserDeviceRepository userDeviceRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final VerificationOtpRepository verificationOtpRepository;
    private final OtpService otpService;

    private static final EmailValidator emailValidator = EmailValidator.getInstance();

    private final static String TOKEN_TYPE = "Bearer";
    private final static int COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60; // 30 days

    @Transactional
    public UserRegisterResponseDTO signUp(UserRegisterRequestDTO userRegisterRequestDTO) {
        if ((userRegisterRequestDTO.getEmail() == null || userRegisterRequestDTO.getEmail().isBlank()) &&
                (userRegisterRequestDTO.getMobileNumber() == null || userRegisterRequestDTO.getMobileNumber().isBlank())) {

            throw new InvalidCredentialsException("Either email or mobile required");
        }

        if (userRegisterRequestDTO.getEmail() != null &&
                authUserRepository.findByEmail(userRegisterRequestDTO.getEmail()).isPresent()) {

            throw new UserAlreadyExistException("Email already registered");
        }

        if (userRegisterRequestDTO.getMobileNumber() != null &&
                authUserRepository.findByMobileNumber(userRegisterRequestDTO.getMobileNumber()).isPresent()) {

            throw new UserAlreadyExistException("Mobile already registered");
        }

        if (userRegisterRequestDTO.getPassword() == null || userRegisterRequestDTO.getPassword().isBlank()) {
            throw new InvalidCredentialsException("Password is required");
        }

        AuthUser newUser = new AuthUser();
        newUser.setEmail(userRegisterRequestDTO.getEmail());
        newUser.setMobileNumber(userRegisterRequestDTO.getMobileNumber());
        newUser.setPasswordHash(passwordEncoder.encode(userRegisterRequestDTO.getPassword()));
        newUser.setRole(Role.USER);
        newUser.setEmailVerified(false);
        newUser.setMobileVerified(false);

        AuthUser savedUser = authUserRepository.save(newUser);

        return UserRegisterResponseDTO
                .builder()
                .message("User Register Successfully")
                .emailVerificationRequired(savedUser.getEmail() != null)
                .mobileVerificationRequired(savedUser.getMobileNumber() != null)
                .build();
    }

    @Transactional
    public UserLoginResponseDTO signIn(UserLoginRequestDTO userPasswordLoginDTO, HttpServletRequest request, HttpServletResponse response, String ipAddress) {

        if ((userPasswordLoginDTO.getMobileNumber() == null || userPasswordLoginDTO.getMobileNumber().isBlank()) &&
                (userPasswordLoginDTO.getEmail() == null || userPasswordLoginDTO.getEmail().isBlank())) {
            throw new InvalidCredentialsException("Either email or mobile required");
        }

        AuthUser user;
        if (userPasswordLoginDTO.getMobileNumber() != null && !userPasswordLoginDTO.getMobileNumber().isBlank()) {
            user = authUserRepository
                    .findByMobileNumber(userPasswordLoginDTO.getMobileNumber())
                    .orElseThrow(() -> new UserNotFound("User not found"));
        } else {
            user = authUserRepository
                    .findByEmail(userPasswordLoginDTO.getEmail())
                    .orElseThrow(() -> new UserNotFound("User not found"));
        }

        boolean passwordMatches = passwordEncoder.matches(userPasswordLoginDTO.getPassword(), user.getPasswordHash());

        if (!passwordMatches) {
            throw new InvalidCredentialsException("Invalid Password");
        }

        boolean emailVerification = user.getEmail() != null && !user.isEmailVerified();
        boolean mobileVerification = user.getMobileNumber() != null && !user.isMobileVerified();

        if (emailVerification || mobileVerification) {
            return UserLoginResponseDTO
                    .builder()
                    .status("Verification Required")
                    .userId(user.getUserId().toString())
                    .role(user.getRole().toString())
                    .emailVerificationRequired(user.getEmail() != null && !user.isEmailVerified())
                    .mobileVerificationRequired(user.getMobileNumber() != null && !user.isMobileVerified())
                    .build();
        }

        String accessToken = jwtService.generateAccessToken(user.getUserId().toString(), user.getRole().toString());
        String refreshToken = jwtService.generateRefreshToken(user.getUserId().toString(), user.getRole().toString());

        UserDevice device = new UserDevice();
        device.setDeviceId(deviceIdGenerator());
        device.setRefreshTokenHash(jwtService.getRefreshTokenHash(refreshToken));
        device.setIpAddress(ipAddress);
        device.setRevoked(false);
        device.setExpiresAt(LocalDateTime.now().plusMonths(1));
        device.setUser(user);
        device.setUserAgent(request.getHeader("User-Agent"));

        userDeviceRepository.save(device);

        addDeviceIdCookie(response, device.getDeviceId());

        addRefreshTokenCookie(response, refreshToken);

        return UserLoginResponseDTO
                .builder()
                .status("Login Successful")
                .userId(user.getUserId().toString())
                .role(user.getRole().toString())
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE)
                .build();
    }

    @Transactional
    public UserRefreshTokenResponse refreshToken(HttpServletResponse response, HttpServletRequest request) {
        String refreshToken = getCookieValue(request, "refresh-token");
        String deviceId = getCookieValue(request, "device-id");

        if (refreshToken == null)
            throw new InvalidCredentialsException("Refresh token not found in cookies");

        if (deviceId == null)
            throw new InvalidCredentialsException("Device ID not found in cookies");

        String oldHash = jwtService.getRefreshTokenHash(refreshToken);

        UserDevice device = userDeviceRepository.findByDeviceId(deviceId);

        if (device == null)
            throw new UserNotFound("Device not found");

        //checking if the device is revoked or not and if the device is expired or not and if the old hash doest matches means malicious hacker try to use old refresh toke ( this is called refresh token rotation reuse detection)
        boolean isValid =
                !device.isRevoked() &&
                        device.getExpiresAt().isAfter(LocalDateTime.now()) &&
                        oldHash.equals(device.getRefreshTokenHash());

        if (!isValid) {
            if (!oldHash.equals(device.getRefreshTokenHash())) {
                userDeviceRepository.revokeAllUserDevices(device.getUser().getUserId());
                throw new InvalidCredentialsException("Potential token reuse detected. All sessions revoked.");
            }

            throw new InvalidCredentialsException("Refresh token expired or revoked");
        }

        String newAccessToken = jwtService.generateAccessToken(
                device.getUser().getUserId().toString(),
                device.getUser().getRole().toString()
        );

        String newRefreshToken = jwtService.generateRefreshToken(
                device.getUser().getUserId().toString(),
                device.getUser().getRole().toString()
        );

        String newHash = jwtService.getRefreshTokenHash(newRefreshToken);


        device.setRefreshTokenHash(newHash);
        device.setExpiresAt(LocalDateTime.now().plusMonths(1));
        userDeviceRepository.save(device);

        addRefreshTokenCookie(response, newRefreshToken);

        return UserRefreshTokenResponse
                .builder()
                .accessToken(newAccessToken)
                .build();
    }

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String deviceId = getCookieValue(request, "device-id");

        if (deviceId != null) {
            UserDevice device = userDeviceRepository.findByDeviceId(deviceId);

            if (device != null) {
                device.setRevoked(true);
                userDeviceRepository.save(device);
            }
        }

        expireRefreshTokenCookie(response, deviceId);
        expireDeviceIdCookie(response, deviceId);
    }

    @Transactional
    public void sendEmailVerificationLink(String email) {

        Optional<AuthUser> optionalUser = authUserRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            log.info("Email {} not found. Skipping verification email.", email);
            return;
        }
        AuthUser user = optionalUser.get();
        if (user.isEmailVerified()) {
            log.info("Email {} already verified. Skipping verification email.", email);
            return;
        }
        verificationTokenRepository.deleteByUserAndType(
                user, VerificationType.EMAIL_VERIFICATION
        );

        String rawToken = UUID.randomUUID().toString();

        String hashedToken = jwtService.getTokenHash(rawToken);

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setTokenHash(hashedToken);
        verificationToken.setUser(user);
        verificationToken.setCreatedAt(LocalDateTime.now());
        verificationToken.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        verificationToken.setUsed(false);
        verificationToken.setType(VerificationType.EMAIL_VERIFICATION);

        verificationTokenRepository.save(verificationToken);

        String verificationLink =
                "https://netflix/verify?token=" + rawToken;

        log.info("Sending verification email to {} with link: {}", email, verificationLink);
        emailService.sendVerificationEmail(user.getEmail(), verificationLink);
    }

    @Transactional
    public void verifyEmail(String token) {
        String tokenHash = jwtService.getTokenHash(token);

        VerificationToken verificationToken = verificationTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid or expired token"));

        if (verificationToken.isUsed() || verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidCredentialsException("Invalid or expired token");
        }
        AuthUser user = verificationToken.getUser();
        user.setEmailVerified(true);
        authUserRepository.save(user);

        verificationToken.setUsed(true);
        verificationTokenRepository.save(verificationToken);
    }

    // HELPERS

    public static boolean isEmail(String identifier) {
        return identifier != null && emailValidator.isValid(identifier);
    }

    public static boolean isMobile(String identifier) {
        return identifier != null && identifier.matches("^[6-9]\\d{9}$");
    }

    private String getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refresh-token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        response.addCookie(cookie);
    }

    private static void addDeviceIdCookie(HttpServletResponse response, String deviceId) {
        Cookie cookie = new Cookie("device-id", deviceId);
        cookie.setHttpOnly(false);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        response.addCookie(cookie);
    }

    private static String deviceIdGenerator() {
        return java.util.UUID.randomUUID().toString();
    }

    private static void expireRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refresh-token", refreshToken);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
    }

    private static void expireDeviceIdCookie(HttpServletResponse response, String deviceId) {
        Cookie cookie = new Cookie("device-id", deviceId);
        cookie.setSecure(true);
        cookie.setHttpOnly(false);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
    }

    @Transactional
    public void sendPasswordResetVerification(@NotBlank String identifier) {
        AuthUser user;
        if (isEmail(identifier)) {
            user = authUserRepository.findByEmail(identifier)
                    .orElseThrow(() -> new UserNotFound("User not found"));

            verificationTokenRepository.deleteByUserAndType(user, VerificationType.PASSWORD_RESET);

            String rawToken = UUID.randomUUID().toString();
            String hashToken = jwtService.getTokenHash(rawToken);

            VerificationToken verificationToken = new VerificationToken();
            verificationToken.setTokenHash(hashToken);
            verificationToken.setCreatedAt(LocalDateTime.now());
            verificationToken.setExpiresAt(LocalDateTime.now().plusMinutes(10));
            verificationToken.setUsed(false);
            verificationToken.setType(VerificationType.PASSWORD_RESET);
            verificationToken.setUser(user);

            verificationTokenRepository.save(verificationToken);

            String verificationLink = "https://netflix/reset-password?token=" + rawToken;

            emailService.sendPasswordResetVerificationEmail(user.getEmail(), verificationLink);

        } else if (isMobile(identifier)) {
            user = authUserRepository.findByMobileNumber(identifier)
                    .orElseThrow(() -> new UserNotFound("User not found"));
            verificationOtpRepository.deleteByUserAndType(user, VerificationType.PASSWORD_RESET);

            VerificationOtp otp = new VerificationOtp();
            otp.setUser(user);
            otp.setMobileNumber(identifier);
            otp.setCreatedAt(LocalDateTime.now());
            otp.setExpiredAt(LocalDateTime.now().plusMinutes(10));
            otp.setUsed(false);
            otp.setType(VerificationType.PASSWORD_RESET);
            otp.setOtpHash(null);// for development purpose

            verificationOtpRepository.save(otp);

            otpService.sendOnceTimePassword(identifier);
        } else {
            throw new InvalidCredentialsException("Invalid email or mobile number");
        }
    }
}

