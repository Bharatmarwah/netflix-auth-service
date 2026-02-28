package in.bm.netflix_auth_service.SERVICE;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender javaMailSender;

    @Async
    public void sendVerificationEmail(String email, String verificationLink) {
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

        message.setFrom("randommail123test@gmail.com");
        javaMailSender.send(message);
    }




}
