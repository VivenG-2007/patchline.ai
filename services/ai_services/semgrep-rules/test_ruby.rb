# ruleid: sqli-ruby-find-by-sql-concat
User.find_by_sql("SELECT * FROM users WHERE id = #{id}")
# ok: sqli-ruby-find-by-sql-concat
User.find_by_sql(["SELECT * FROM users WHERE id = ?", id])

# ruleid: sqli-ruby-where-concat
User.where("id = " + id)
# ok: sqli-ruby-where-concat
User.where("id = ?", id)

# ruleid: crypto-md5-ruby
Digest::MD5.hexdigest(id)
# ok: crypto-md5-ruby
Digest::SHA256.hexdigest(id)

# ruleid: crypto-sha1-ruby
Digest::SHA1.hexdigest(id)
# ok: crypto-sha1-ruby
Digest::SHA256.hexdigest(id)
