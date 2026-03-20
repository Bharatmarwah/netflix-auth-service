package in.bm.netflix_auth_service.SERVICE;

import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import com.twilio.type.PhoneNumber;
import in.bm.netflix_auth_service.EXCEPTION.InvalidOtpException;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class OtpService {

    private final static String Twilio_Account_Sid = System.getenv("TWILIO_ACCOUNT_SID");
    private final static String Twilio_Auth_Token = System.getenv("TWILIO_AUTH_TOKEN");
    private final static String Twilio_Service_Sid = System.getenv("TWILIO_SERVICE_SID");

    public void sendOnceTimePassword(@NotBlank String identifier) {
        try{
            log.info("Sending OTP to {}", identifier);
            Twilio.init(Twilio_Account_Sid,Twilio_Auth_Token);
            Verification verification = Verification.creator(
                    Twilio_Service_Sid,
                    "+91"+identifier,
                    "sms"
            ).create();
        }catch (Exception e){
            log.error("Error sending OTP to {}: {}", identifier, e.getMessage());
            throw new RuntimeException("Failed to send OTP. Please try again later.");
        }

    }

    public void verifyOtp(@Pattern(regexp = "^[0-9]{10}$",message = "Invalid mobile number") String mobileNumber, @NotBlank String code) {
      try{
        VerificationCheck verificationCheck = com.twilio.rest.verify.v2.service
                .VerificationCheck.creator(Twilio_Service_Sid)
                .setTo("+91" + mobileNumber)
                .setCode(code)
                .create();

        if (!"approved".equals(verificationCheck.getStatus())) {
            throw new InvalidOtpException("Invalid or expire OTP");
        }
    }
      catch (Exception e){
          log.error("Error verifying code of {}: {}", mobileNumber, e.getMessage());
          throw new RuntimeException("Failed to send OTP. Please try again later.");
      }
      }
}
