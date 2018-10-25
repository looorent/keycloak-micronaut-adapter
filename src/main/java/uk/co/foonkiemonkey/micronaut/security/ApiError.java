package uk.co.foonkiemonkey.micronaut.security;

/**
 * ApiError
 */
/**
 *
 * @author jearm
 */
public class ApiError {

    private Long timestamp;
    private int status;
    private String error;
    private String exeption;
    private String message;
    private String path;

    public ApiError(Long timestamp, int status, String error, String exeption, String message) {
        this.timestamp = timestamp;
        this.status = status;
        this.error = error;
        this.exeption = exeption;
        this.message = message;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getExeption() {
        return exeption;
    }

    public void setExeption(String exeption) {
        this.exeption = exeption;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

}