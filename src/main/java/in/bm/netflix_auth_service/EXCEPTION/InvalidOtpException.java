package in.bm.netflix_auth_service.EXCEPTION;

public class InvalidOtpException extends RuntimeException {
    public InvalidOtpException(String message) {
        super(message);
    }
}
