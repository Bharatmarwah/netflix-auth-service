package in.bm.netflix_auth_service.SERVICE;

import in.bm.netflix_auth_service.ENTITY.AuthUser;
import in.bm.netflix_auth_service.ENTITY.Role;
import in.bm.netflix_auth_service.ENTITY.UserDevice;
import in.bm.netflix_auth_service.EXCEPTION.InvalidCredentialsException;
import in.bm.netflix_auth_service.EXCEPTION.UserAlreadyExistException;
import in.bm.netflix_auth_service.EXCEPTION.UserNotFound;
import in.bm.netflix_auth_service.REPOSITORY.AuthUserRepository;
import in.bm.netflix_auth_service.REPOSITORY.UserDeviceRepository;
import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRefreshTokenResponse;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import jakarta.servlet.http.Cookie;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
public class AuthUserService {

    private final AuthUserRepository authUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserDeviceRepository userDeviceRepository;

    public static final String TOKEN_TYPE = "Bearer";

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

        AuthUser u = new AuthUser();
        u.setEmail(userRegisterRequestDTO.getEmail());
        u.setMobileNumber(userRegisterRequestDTO.getMobileNumber());
        u.setPasswordHash(passwordEncoder.encode(userRegisterRequestDTO.getPassword()));
        u.setRole(Role.USER);
        u.setEmailVerified(false);
        u.setMobileVerified(false);


        AuthUser savedUser = authUserRepository.save(u);

        return UserRegisterResponseDTO
                .builder()
                .message("User Register Successfully")
                .emailVerificationRequired(savedUser.getEmail() != null)
                .mobileVerificationRequired(savedUser.getMobileNumber() != null)
                .build();
    }

    @Transactional
    public UserLoginResponseDTO signIn(UserLoginRequestDTO userPasswordLoginDTO, HttpServletResponse response, String ipAddress) {

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

        String accessToken = jwtService.generateAccessToken(user.getUserId().toString(), user.getRole().toString());
        String refreshToken = jwtService.generateRefreshToken(user.getUserId().toString(), user.getRole().toString());

        UserDevice device = new UserDevice();
        device.setDeviceId(deviceIdGenerator());
        device.setRefreshTokenHash(jwtService.getRefreshTokenHash(refreshToken));
        device.setIpAddress(ipAddress);
        device.setRevoked(false);
        device.setExpiresAt(LocalDateTime.now().plusMonths(1));
        device.setUser(user);

        userDeviceRepository.save(device);

        addDeviceIdCookie(response, device.getDeviceId());

        addRefreshTokenCookie(response, refreshToken);

        return UserLoginResponseDTO
                .builder()
                .userId(user.getUserId().toString())
                .role(user.getRole().toString())
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE)
                .build();
    }

    @Transactional
    public UserRefreshTokenResponse refreshToken(HttpServletResponse response, HttpServletRequest request) {
        String refreshToken = null;
        String deviceId = null;

        Cookie[] cookies = request.getCookies();
        if (cookies == null)
            throw new InvalidCredentialsException("No cookies found");

        for (Cookie c : cookies) {
            if ("refresh-token".equals(c.getName())) {
                refreshToken = c.getValue();
            }
            if ("device-id".equals(c.getName())) {
                deviceId = c.getValue();
            }
        }

        if (refreshToken == null)
            throw new InvalidCredentialsException("Refresh token not found in cookies");

        if (deviceId == null)
            throw new InvalidCredentialsException("Device ID not found in cookies");

        String oldHash = jwtService.getRefreshTokenHash(refreshToken);

        UserDevice device = userDeviceRepository.findByDeviceId(deviceId);

        if (device == null)
            throw new UserNotFound("Device not found");

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

        return UserRefreshTokenResponse.builder().accessToken(newAccessToken).build();
    }

    private static void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refresh-token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(30 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    private static void addDeviceIdCookie(HttpServletResponse response, String deviceId) {
        Cookie cookie = new Cookie("device-id", deviceId);
        cookie.setHttpOnly(false);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(30 * 24 * 60 * 60);
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
    public void logout(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();

        String deviceId = null;

        if (cookies!= null) {
            for (Cookie c : cookies) {
                if ("device-id".equals(c.getName())) {
                    deviceId = c.getValue();
                }
            }
        }

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

}

