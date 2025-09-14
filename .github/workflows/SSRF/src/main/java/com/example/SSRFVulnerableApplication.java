package src.main.java.com.example;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

@SpringBootApplication
@RestController
public class SsrfVulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApplication.class, args);
    }

    /**
     * VULNERABLE ENDPOINT
     * This endpoint fetches content from a user-provided URL and returns it.
     * It does not validate or sanitize the 'url' parameter, making it
     * vulnerable to Server-Side Request Forgery (SSRF).
     *
     * @param url The URL of the image to fetch.
     * @return The raw bytes of the content from the URL.
     */
    @GetMapping("/proxy-image")
    public ResponseEntity<byte[]> getImage(@RequestParam String url) {
        try {
            // --- VULNERABLE PART ---
            // The application creates a URL object directly from user input without any validation.
            // This is the root cause of the SSRF vulnerability.
            URL imageUrl = new URL(url);
            URLConnection connection = imageUrl.openConnection();
            connection.connect(); // The server makes a request to the user-provided URL here.

            try (InputStream inputStream = connection.getInputStream()) {
                byte[] content = inputStream.readAllBytes();
                HttpHeaders headers = new HttpHeaders();
                headers.add(HttpHeaders.CONTENT_TYPE, connection.getContentType());
                return new ResponseEntity<>(content, headers, HttpStatus.OK);
            }
        } catch (Exception e) {
            // Return a generic error message. Error messages can sometimes leak
            // information about the internal network structure.
            return new ResponseEntity<>(e.getMessage().getBytes(), HttpStatus.BAD_REQUEST);
        }
    }
}
