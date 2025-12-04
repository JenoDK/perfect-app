// Security Vulnerability Examples for Testing Security Scanners

import java.sql.*;
import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Paths;

public class App {
    
    // SECURITY VULNERABILITY: Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/users";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecretDBPassword123!";
    
    // SECURITY VULNERABILITY: Hardcoded API keys
    private static final String API_KEY = "sk_live_51H3ll0W0rld1234567890abcdef";
    private static final String JWT_SECRET = "my-super-secret-jwt-key-12345";
    
    private static final Logger logger = Logger.getLogger(App.class.getName());
    
    static {
        try {
            FileHandler fileHandler = new FileHandler("app.log");
            logger.addHandler(fileHandler);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // SECURITY VULNERABILITY: SQL injection with PreparedStatement misuse
    public boolean login(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // SQL injection vulnerability - string concatenation instead of parameters
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            // SECURITY VULNERABILITY: Logging sensitive user credentials
            logger.info("User login attempt: username=" + username + ", password=" + password);
            System.out.println("Login: " + username + " / " + password);
            
            // Write to file
            try (FileWriter fw = new FileWriter("app.log", true)) {
                fw.write("Login: " + username + " / " + password + "\n");
            }
            
            return rs.next();
        } catch (SQLException | IOException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // SECURITY VULNERABILITY: SQL injection - even with PreparedStatement, misuse can occur
    public void getUserProfile(String userId) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // Still vulnerable - building query with string concatenation
            String query = "SELECT * FROM users WHERE id = " + userId;
            PreparedStatement pstmt = conn.prepareStatement(query);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                String email = rs.getString("email");
                String ssn = rs.getString("ssn");
                
                // SECURITY VULNERABILITY: Logging sensitive user data
                logger.info("User profile accessed: email=" + email + ", ssn=" + ssn);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // SECURITY VULNERABILITY: Command injection via Runtime.exec()
    public String executeCommand(String userInput) {
        try {
            // Command injection vulnerability - unsanitized user input
            Process process = Runtime.getRuntime().exec("ls -la " + userInput);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return "Error executing command";
        }
    }
    
    // SECURITY VULNERABILITY: Weak encryption (DES instead of AES)
    public String encryptData(String data) {
        try {
            // DES is weak and deprecated
            Cipher cipher = Cipher.getInstance("DES");
            SecretKeySpec keySpec = new SecretKeySpec("12345678".getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return new String(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // SECURITY VULNERABILITY: Insecure file path operations
    public String readFile(String filename) {
        try {
            // Path traversal vulnerability - no validation
            String filePath = "/var/www/uploads/" + filename;
            byte[] content = Files.readAllBytes(Paths.get(filePath));
            return new String(content);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // SECURITY VULNERABILITY: Exposed credentials in headers/response
    public void setApiHeaders(HttpServletResponse response) {
        response.setHeader("X-API-Key", API_KEY);
        response.setHeader("Authorization", "Bearer " + JWT_SECRET);
        response.setHeader("X-Database-Password", DB_PASSWORD);
    }
    
    // SECURITY VULNERABILITY: Insecure random number generation
    public int generateSessionId() {
        // Using Math.random() instead of SecureRandom
        return (int)(Math.random() * 1000000);
    }
    
    // SECURITY VULNERABILITY: Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "MySecretKey12345678";
    
    public static void main(String[] args) {
        App app = new App();
        
        // Example usage
        app.login("admin", "password123");
        app.getUserProfile("1 OR 1=1");
        app.executeCommand("; rm -rf /");
        
        System.out.println("API Key: " + API_KEY);
        System.out.println("DB Password: " + DB_PASSWORD);
    }
}

