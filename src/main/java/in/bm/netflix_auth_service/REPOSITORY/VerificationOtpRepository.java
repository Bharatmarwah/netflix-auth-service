package in.bm.netflix_auth_service.REPOSITORY;

import in.bm.netflix_auth_service.ENTITY.AuthUser;
import in.bm.netflix_auth_service.ENTITY.VerificationOtp;
import in.bm.netflix_auth_service.ENTITY.VerificationType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationOtpRepository extends JpaRepository<VerificationOtp,Long> {
    void deleteByUserAndType(AuthUser user, VerificationType verificationType);
}
