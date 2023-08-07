const mysql = require('mysql');
const bcrypt = require('bcrypt');

// Create a MySQL connection pool
const pool = mysql.createPool({
  connectionLimit: 100,
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'accounts',
});

// Define the account table schema
const accountTable = `
CREATE TABLE IF NOT EXISTS accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  fullName VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  phoneNumber VARCHAR(255) NOT NULL,
  profilePhoto VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(255) NOT NULL
)`;

// Define the posts table schema
const postsTable = `
CREATE TABLE IF NOT EXISTS posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  content TEXT NOT NULL,
  userid INT,
  FOREIGN KEY (userid) REFERENCES accounts(id) ON DELETE CASCADE
)`;



// Create the accounts table if it doesn't exist
pool.query(accountTable, (error, results, fields) => {
  if (error) {
    console.error('Error creating accounts table:', error);
    return;
  }
  console.log('Accounts table created successfully');

  // Create the posts table if it doesn't exist
  pool.query(postsTable, (error, results, fields) => {
    if (error) {
      console.error('Error creating posts table:', error);
      return;
    }
    console.log('Posts table created successfully');

      // Add admin account if it doesn't exist
      const adminEmail = 'admin@gmail.com';
      const adminPassword = 'adminacc';
      const adminRole = 'admin';
      pool.query(
        'SELECT * FROM accounts WHERE email = ?',
        [adminEmail],
        async (error, results) => {
          if (error) {
            console.error('Error checking for admin account:', error);
            return;
          } else if (results.length == 0) {
            const hashedPassword = await bcrypt.hash(adminPassword, 10);
            let query =
              'INSERT INTO accounts (fullName, email, phoneNumber, profilePhoto, password, role) VALUES(?,?,?,?,?,?)';
            pool.query(
              query,
              ['Admin', adminEmail, '00000000000', '', hashedPassword, 'admin'],
              (err, result) => {
                if (err) {
                  console.log('Admin account not made');
                } else {
                  console.log('Admin account created successfully');
                }
              }
            );
          }
        }
      );
   
  });
});

exports.node = pool;
