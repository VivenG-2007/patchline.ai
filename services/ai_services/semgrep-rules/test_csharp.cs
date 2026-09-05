using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Diagnostics;

class Test {
  void F(string id, SqlCommand cmd) {
    // ruleid: sqli-cs-sqlcommand-concat
    var c1 = new SqlCommand("SELECT * FROM users WHERE id = " + id, conn);
    // ok: sqli-cs-sqlcommand-concat
    var c1b = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);

    // ruleid: sqli-cs-entityframework-raw
    db.FromSqlRaw("SELECT * FROM users WHERE id = " + id);
    // ok: sqli-cs-entityframework-raw
    db.FromSqlRaw("SELECT * FROM users WHERE id = {0}", id);

    // ruleid: cmdi-cs-process-start
    Process.Start("ping " + id, args);
    // ok: cmdi-cs-process-start
    Process.Start("ping", id);

    // ruleid: crypto-des
    var des = TripleDES.Create();
    // ok: crypto-des
    var aes = Aes.Create();

    // ruleid: crypto-ecb-mode
    var mode = CipherMode.ECB;
    // ok: crypto-ecb-mode
    var mode2 = CipherMode.CBC;

    // ruleid: crypto-cbc-no-iv
    Cipher.getInstance("AES/CBC/PKCS5Padding");
    // ok: crypto-cbc-no-iv
    var aesGcm = Aes.Create();

    // ruleid: crypto-rc4
    var rc4 = RC4.Create();
    // ok: crypto-rc4
    var aes2 = Aes.Create();

    // ruleid: crypto-md5
    var md5 = MD5.Create();
    // ok: crypto-md5
    var sha256 = SHA256.Create();

    // ruleid: crypto-sha1
    var sha1 = SHA1.Create();
    // ok: crypto-sha1
    var sha256b = SHA256.Create();
  }

  static void G() {
    // ruleid: crypto-rsa-small-key
    RSA.Create(1024);
    // ok: crypto-rsa-small-key
    RSA.Create(2048);
  }
}
