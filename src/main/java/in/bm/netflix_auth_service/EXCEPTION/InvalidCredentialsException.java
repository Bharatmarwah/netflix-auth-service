package in.bm.netflix_auth_service.EXCEPTION;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}
