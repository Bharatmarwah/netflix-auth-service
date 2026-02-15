package in.bm.netflix_auth_service.SERVICE;

import in.bm.netflix_auth_service.ENTITY.AuthUser;
import in.bm.netflix_auth_service.ENTITY.Role;
import in.bm.netflix_auth_service.EXCEPTION.InvalidCredentialsException;
import in.bm.netflix_auth_service.EXCEPTION.UserAlreadyExistException;
import in.bm.netflix_auth_service.EXCEPTION.UserNotFound;
import in.bm.netflix_auth_service.REPOSITORY.AuthUserRepository;
import in.bm.netflix_auth_service.RequestDTO.UserLoginRequestDTO;
import in.bm.netflix_auth_service.RequestDTO.UserRegisterRequestDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserLoginResponseDTO;
import in.bm.netflix_auth_service.ResponseDTO.UserRegisterResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class AuthUserService {

    private final AuthUserRepository authUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;

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

    public UserLoginResponseDTO signIn(UserLoginRequestDTO userPasswordLoginDTO) {

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

        return UserLoginResponseDTO
                .builder()
                .userId(user.getUserId().toString())
                .role(user.getRole().toString())
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE)
                .build();
    }

}
