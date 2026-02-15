package in.bm.netflix_auth_service.EXCEPTION;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UserNotFound.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String,Object> handleUserNotFoundExceptions(UserNotFound ex){
        return Map.of("message",ex.getMessage(),
                "status",HttpStatus.BAD_REQUEST.value(),
                "timestamp", LocalDateTime.now());
    }

    @ExceptionHandler(UserAlreadyExistException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Map<String,Object> handleUserAlreadyExistExceptions(UserAlreadyExistException ex){
        return Map.of("message",ex.getMessage(),
                "status",HttpStatus.CONFLICT.value(),
                "timestamp", LocalDateTime.now());
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String,Object> handleInvalidCredentialsExceptions(InvalidCredentialsException ex){
        return Map.of("message",ex.getMessage(),
                "status",HttpStatus.UNAUTHORIZED.value(),
                "timestamp", LocalDateTime.now());
    }


}
