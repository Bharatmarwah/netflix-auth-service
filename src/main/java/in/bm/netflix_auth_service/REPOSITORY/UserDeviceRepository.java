package in.bm.netflix_auth_service.REPOSITORY;

import in.bm.netflix_auth_service.ENTITY.UserDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface UserDeviceRepository extends JpaRepository<UserDevice,Long> {

    UserDevice findByDeviceId(String deviceId);

    @Transactional
    @Modifying
    @Query("UPDATE UserDevice ud SET ud.isRevoked = true WHERE ud.user.userId = :userId")
    int revokeAllUserDevices(@Param("userId") UUID userId);
}
