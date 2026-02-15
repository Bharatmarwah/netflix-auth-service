package in.bm.netflix_auth_service.EXCEPTION;

public class UserAlreadyExistException extends RuntimeException {
    public UserAlreadyExistException(String message) {
        super(message);
    }
}
