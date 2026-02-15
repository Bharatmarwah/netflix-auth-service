package in.bm.netflix_auth_service.REPOSITORY;

import in.bm.netflix_auth_service.ENTITY.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;


@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {

    Optional<AuthUser> findByEmail(String email);

    Optional<AuthUser> findByMobileNumber(String mobileNumber);
}
