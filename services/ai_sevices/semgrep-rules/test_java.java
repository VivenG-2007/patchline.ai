import java.sql.*;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.util.Random;
import java.security.SecureRandom;

public class Test {
  void f(String id, Statement stmt, PreparedStatement pstmt) throws Exception {
    // ruleid: sqli-java-statement-concat
    stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    // ok: sqli-java-statement-concat
    pstmt.executeQuery();

    // ruleid: sqli-java-indirect-concat
    String query = "SELECT * FROM users WHERE id = " + id;
    stmt.executeQuery(query);
    // ok: sqli-java-indirect-concat
    String query2 = "SELECT * FROM users WHERE id = ?";
    pstmt.setString(1, id);

    // ruleid: cmdi-java-runtime-exec
    Runtime.getRuntime().exec("ping " + id);
    // ok: cmdi-java-runtime-exec
    ProcessBuilder pb = new ProcessBuilder("ping", id);

    // ruleid: cmdi-java-processbuilder-command
    ProcessBuilder pb2 = new ProcessBuilder("ping " + id);
    // ok: cmdi-java-processbuilder-command
    ProcessBuilder pb3 = new ProcessBuilder("ping", id);

    // ruleid: path-traversal-java-file
    FileInputStream fis = new FileInputStream(id);
    // ok: path-traversal-java-file
    FileInputStream fis2 = new FileInputStream("static/config.json");

    // ruleid: crypto-des
    Cipher c1 = Cipher.getInstance("DES/ECB/PKCS5Padding");
    // ok: crypto-des
    Cipher c1b = Cipher.getInstance("AES/GCM/NoPadding");

    // ruleid: crypto-ecb-mode
    Cipher c2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
    // ok: crypto-ecb-mode
    Cipher c2b = Cipher.getInstance("AES/GCM/NoPadding");

    // ruleid: crypto-cbc-no-iv
    Cipher c3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
    // ok: crypto-cbc-no-iv
    Cipher c3b = Cipher.getInstance("AES/GCM/NoPadding");

    // ruleid: crypto-rc4
    Cipher c4 = Cipher.getInstance("RC4");
    // ok: crypto-rc4
    Cipher c4b = Cipher.getInstance("AES/GCM/NoPadding");

    // ruleid: crypto-md5
    MessageDigest md = MessageDigest.getInstance("MD5");
    // ok: crypto-md5
    MessageDigest md2 = MessageDigest.getInstance("SHA-256");

    // ruleid: crypto-sha1
    MessageDigest sh = MessageDigest.getInstance("SHA-1");
    // ok: crypto-sha1
    MessageDigest sh2 = MessageDigest.getInstance("SHA-256");

    // ruleid: insecure-deserialization-java
    Object o = new ObjectInputStream(inStream).readObject();
    // ok: insecure-deserialization-java
    Object o2 = jsonMapper.readValue(inStream, MyClass.class);
  }
}

// ruleid: crypto-weak-random-java
Random secretToken = new Random(); // token
// ok: crypto-weak-random-java
Random jitter = new Random();

// ruleid: crypto-rsa-small-key
KeyPairGenerator.getInstance("RSA").initialize(1024);
// ok: crypto-rsa-small-key
KeyPairGenerator.getInstance("RSA").initialize(2048);

interface UserRepo {
  // ruleid: sqli-jpa-query
  @Query("SELECT u FROM User u WHERE u.id = " + "id")
  User findRaw(String id);

  // ok: sqli-jpa-query
  @Query("SELECT u FROM User u WHERE u.id = :id")
  User findSafe(@Param("id") String id);
}
