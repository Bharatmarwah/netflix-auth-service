package in.bm.netflix_auth_service.EXCEPTION;

public class UserNotFound extends RuntimeException {
    public UserNotFound(String message) {
        super(message);
    }
}
