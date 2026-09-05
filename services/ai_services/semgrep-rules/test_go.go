package main

import (
    "crypto/des"
    "database/sql"
    "os/exec"
)

func f(id string, db *sql.DB) {
    // ruleid: sqli-go-db-query-concat
    db.Query("SELECT * FROM users WHERE id = " + id)
    // ok: sqli-go-db-query-concat
    db.Query("SELECT * FROM users WHERE id = ?", id)

    // ruleid: sqli-go-gorm-raw
    gormDb.Raw("SELECT * FROM users WHERE id = " + id)
    // ok: sqli-go-gorm-raw
    gormDb.Raw("SELECT * FROM users WHERE id = ?", id)

    // ruleid: cmdi-go-exec-command
    exec.Command("ping " + id)
    // ok: cmdi-go-exec-command
    exec.Command("ping", id)

    // ruleid: crypto-des
    cipher, _ := des.NewCipher(key)
    _ = cipher

    // ruleid: crypto-rc4
    c, _ := rc4.NewCipher(key)
    _ = c

    // ruleid: crypto-md5
    h := md5.New()
    _ = h

    // ruleid: crypto-sha1
    h2 := sha1.New()
    _ = h2

    // ruleid: crypto-weak-random-go
    token := rand.Intn(1000000) // token
    _ = token
    // ok: crypto-weak-random-go
    jitter := rand.Intn(100)
    _ = jitter

    // ruleid: crypto-rsa-small-key
    rsa.GenerateKey(rand.Reader, 1024)
    // ok: crypto-rsa-small-key
    rsa.GenerateKey(rand.Reader, 2048)
}
