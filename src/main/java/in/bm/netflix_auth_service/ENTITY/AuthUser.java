    package in.bm.netflix_auth_service.ENTITY;

    import jakarta.persistence.*;
    import lombok.AllArgsConstructor;
    import lombok.Getter;
    import lombok.NoArgsConstructor;
    import lombok.Setter;
    import org.hibernate.annotations.Check;

    import java.util.List;
    import java.util.UUID;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @Table(name = "auth_user_db")
    @Entity
    @Check(constraints = "email IS NOT NULL OR mobile_number IS NOT NULL")
    public class AuthUser {

        @Id
        @GeneratedValue(strategy = GenerationType.UUID)
        private UUID userId;

        @Column(name = "email",unique = true)
        private String email;

        @Column(name = "mobile_number", unique = true)
        private String mobileNumber;

        @Column(name = "password_hash",nullable = false)
        private String passwordHash;

        @Column(nullable = false)
        @Enumerated(EnumType.STRING)
        private Role role;

        private boolean emailVerified;

        private boolean mobileVerified;

        @OneToMany(mappedBy = "user",cascade = CascadeType.ALL,orphanRemoval = true)
        private List<UserDevice> userDevices;



    }
