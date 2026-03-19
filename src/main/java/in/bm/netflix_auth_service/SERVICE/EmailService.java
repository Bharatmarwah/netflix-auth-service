package in.bm.netflix_auth_service.SERVICE;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender javaMailSender;

    @Async
    public void sendVerificationEmail(String email, String verificationLink) {
        log.info("Sending verification email to {}", email);
        SimpleMailMessage message  = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Verify Your Account");
        message.setText(
                "Hi,\n\n" +
                        "Thank you for signing up.\n\n" +
                        "Please verify your email address by clicking the link below:\n\n" +
                        verificationLink + "\n\n" +
                        "This verification link will expire in 15 minutes.\n\n" +
                        "If you did not request this, please ignore this email. " +
                        "No changes will be made to your account.\n\n" +
                        "For security reasons, do not share this link with anyone.\n\n" +
                        "Thanks,\n" +
                        "The Team"
        );

        message.setFrom("bharatmarwah4@gamil.com");
        javaMailSender.send(message);

        log.info("Verification email sent to {}", email);
    }

    @Async
    public void sendPasswordResetVerificationEmail(String email, String verificationLink) {
        log.info("Sending password reset verification email to {}", email);
        SimpleMailMessage message  = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Password Reset Request");
        message.setText(
                "Hi,\n\n" +
                        "We received a request to reset your password.\n\n" +
                        "Please reset your password by clicking the link below:\n\n" +
                        verificationLink + "\n\n" +
                        "This password reset link will expire in 10 minutes.\n\n" +
                        "If you did not request this, please ignore this email. " +
                        "No changes will be made to your account.\n\n" +
                        "For security reasons, do not share this link with anyone.\n\n" +
                        "Thanks,\n" +
                        "The Team"
        );

        message.setFrom("bharatmarwah4@gmail.com");
        javaMailSender.send(message);

        log.info("Password reset verification email sent to {}", email);
    }
}
