const express = require('express');
const fileUpload = require('express-fileupload');
const bcrypt = require('bcrypt');
const Account = require('./model/accountSchema');
const path = require('path');
const app = express();
const session = require('express-session');
const mime = require('mime-types');
const rateLimit = require('express-rate-limit');
const fs = require('fs')
const fileType = require('file-type');
const port = 4000;


// Set up the 'hbs' view engine
app.set('view engine', 'hbs');
app.use(express.static(__dirname));
app.use(express.json());
app.use(fileUpload({
  useTempFiles: true,
  tempFileDir: './temp', // temp path
}));
app.set('views', './frontend');


app.use(session({
  secret: 'supersecretsessionkeynamedyomadalimakuha',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 60 * 1000 // 30 mins in milliseconds
  }
}))

const ensureAuth = (req, res, next) => { //for the future pag di na res.render yung login lang
  if (req.session.auth)
    next()
  else
    res.redirect('/')
}

const ensureNotAuth = (req, res, next) => {
  if(req.session.auth){
    return res.redirect('/main');
  }
  next();
}

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
	max: 5, // maximum of 5 failed login attempts
  skipSuccessfulRequests: true,
  message: "Too many login attempts, please try again later"
})

// Define a route for '/register' to render the registration template
app.get('/', ensureNotAuth, (req, res) => {
  
  res.render('login.hbs');
});
// Handle the login form submission
app.post('/login', loginLimit, ensureNotAuth, async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    
    let user;
    try {
      // Find the user by email
      let query = 'SELECT * FROM accounts WHERE email = ?';
      Account.node.query(query, [email], async (error, results) => {
        if (results.length == 0) { // no email matched
          console.error('Error retrieving user:', error);
          return res.send('Invalid Credentials');
        }
        user = Object.values(results[0]);
     
        if (user) {
          // Compare the provided password with the stored hashed password
          Object.values(user)
          const isMatch = await bcrypt.compare(password, user[5]);
    
          if (isMatch) {
            // Passwords match, user is authenticated
            req.session.auth = true;
            req.session.email = email;
            if(user[6] == "user"){// default login
              req.session.isAdmin = false;
              //console.log(user)
              res.render('main.hbs', {profilePhoto: user[4], fullName: user[1], email: user[2], phoneNumber: user[3], role: user[6]});
            }
            else{// user is an admin
              req.session.isAdmin = true
              res.redirect('/administration')
            }
            
            //res.send('Login successful');
          } else {
            // Passwords do not match
            req.session.isAuth = false;
            res.status(404).send('Invalid credentials');
          }
        } else {
          // User not found
          req.session.isAuth = false;
          res.status(404).send('Invalid credentials');
        }
      })

      
    } catch (err) {
      //console.log(err);
      res.send('Error occurred');
    }
  });

app.get('/main', ensureAuth, async (req, res) =>{
  let query = 'SELECT * FROM accounts WHERE email = ?';
  let email = req.session.email;
  if(email){
    Account.node.query(query, [email], async(error, results) => {
      if (results.length == 0) { // no email matched
        console.error('Error retrieving user:', error);
        return res.send('Invalid User');
      }
      user = Object.values(results[0]);
      res.render('main.hbs', {profilePhoto: user[4], fullName: user[1], email: user[2], phoneNumber: user[3], role: user[6]});
    });
  } else {
    res.send('Error occured')
  }
});

// Logout Function
app.get('/logout', ensureAuth, (req, res) => {
  req.session.destroy();
  res.render('login.hbs');
});

// Administration Function
app.get('/administration', ensureAuth, (req, res) => {
  //Check first if the user is actually an admin, to prevent normal user simply typing /administration
  try{
    if(req.session.isAdmin){
     
     
      const query = 'SELECT * FROM accounts WHERE role = ?';
      Account.node.query(query, ['user'], (error, results) => {
        if (error) {
          console.error('Error retrieving users:', error);
          return res.send('Error occurred');
        }

        const users = Object.values(results);

        //console.log('the users:');
        //console.log(users);
        res.render('administration.hbs', {
          users: users,
        });
      });
        
        
    } else {
      res.redirect('/main')
    }
  }
  catch(err){
    //console.log(err)
    res.send('error has occurred')
  }
  

   
 
  
});

// Direct to registration hbs
app.get('/register', ensureNotAuth, (req, res) => {
  res.render('registration.hbs');
});

app.post('/registerdetails', ensureNotAuth, async(req, res) => {
  try{
   
      const profphoto = req.files.profilephoto;
      const fullname = req.body.fullname;
      const email = req.body.email;
      const phone = req.body.phone;
      const password = req.body.password;

      // Input validation using regular expressions
      const emailRegex = /^[a-zA-Z0-9]+([_.-][a-zA-Z0-9]+)*@[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z]{2,})+$/;
      const phoneRegex = /^09\d{9}$/;
      if (!emailRegex.test(email)) {
        fs.unlink(profphoto.tempFilePath, (err) => {
          if (err) {
            //console.error('Failed to delete temporary file:', err);
          } else {
            //console.log('Temporary file deleted');
          }
        });
        return res.send('<script>alert("Invalid email format"); window.location.href = "/register";</script>');
      }

      if (!phoneRegex.test(phone)) {
        fs.unlink(profphoto.tempFilePath, (err) => {
          if (err) {
            //console.error('Failed to delete temporary file:', err);
          } else {
            //console.log('Temporary file deleted');
          }
        });
        return res.send('<script>alert("Invalid phone number"); window.location.href = "/register";</script>');
      }
    
      // Check if any of the input fields are empty
      if (!profphoto || !fullname || !email || !phone || !password) {
        fs.unlink(profphoto.tempFilePath, (err) => {
          if (err) {
            //console.error('Failed to delete temporary file:', err);
          } else {
            //console.log('Temporary file deleted');
          }
        });
        return res.send('<script>alert("Please fill in all fields"); window.location.href = "/register";</script>');
      }
      // Check if the uploaded file is an image
      const fileMimeType = mime.lookup(profphoto.name);
      if (!fileMimeType || !fileMimeType.startsWith('image/')) {
        fs.unlink(profphoto.tempFilePath, (err) => {
          if (err) {
            //console.error('Failed to delete temporary file:', err);
          } else {
            //console.log('Temporary file deleted');
          }
        });
        return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/register";</script>');
      }

      
      const fileData = fs.readFileSync(profphoto.tempFilePath);

      // Validate the magic number
      const fileTypeResult = fileType(fileData);
      if (!fileTypeResult || !fileTypeResult.mime.startsWith('image/')) {
        fs.unlink(profphoto.tempFilePath, (err) => {
          if (err) {
            //console.error('Failed to delete temporary file:', err);
          } else {
            //console.log('Temporary file deleted');
          }
        });
        return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/register";</script>');
      }

        // Check if the email already exists in the database
        let query = "SELECT * from accounts where email = ?";
        Account.node.query(query, [email], async(error, existingUser)=>{
          if(existingUser && existingUser.length > 0){
            //console.log(existingUser)
            fs.unlink(profphoto.tempFilePath, (err) => {
              if (err) {
                //console.error('Failed to delete temporary file:', err);
              } else {
                //console.log('Temporary file deleted');
              }
            });
            return res.send('<script>alert("Email already registered"); window.location.href = "/register";</script>');
          }
          else{ // register the account
            try {
              // Hash the password
              const hashedPassword = await bcrypt.hash(password, 10);
            
              let query = "INSERT INTO accounts (fullName, email, phoneNumber, profilePhoto, password, role) VALUES(?,?,?,?,?,?)";
              Account.node.query(query,[fullname, email, phone, "images/" + profphoto.name, hashedPassword, "user"], (err, result)=>{
                if(err){
                  //console.log(err);
                  return;
                }
                else{
                  //console.log("ADDING THE ACCOUNT:")
                  //console.log(result);
                  const uploadPath = path.join(__dirname, 'images', profphoto.name);
                  profphoto.mv(uploadPath, (error) => {
                    if (error) {
                      //console.log("failed to save photo")
                      //console.log(error);
                    } else {
                      //console.log("ADDED");
                      
                      res.redirect('/')
                    }
                  });
                }
              })
            
            } 
            catch (err) {
              //console.log(err);
            }
          }
        })
  
      
  }
  catch(err){
    console.log(err)
    res.send('<script>alert("Something went wrong"); window.location.href = "/register";</script>');
  }

  
});

app.post('/editAdmin', ensureAuth, async(req, res) => {
  // Input validation using regular expressions
  const email = req.body.email;
  const id = req.body.id;
  const fullname = req.body.fullname;
  const phone = req.body.phone;
  console.log(req.body)
  const emailRegex = /^[a-zA-Z0-9]+([_.-][a-zA-Z0-9]+)*@[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z]{2,})+$/;
  const phoneRegex = /^09\d{9}$/;
  if (!emailRegex.test(email)) {
    return res.send('<script>alert("Invalid email format"); window.location.href = "/administration";</script>');
  }

  if (!phoneRegex.test(phone)) {
    return res.send('<script>alert("Invalid phone number"); window.location.href = "/administration";</script>');
  }

  // Check if the email is still the same
  let query0 = "SELECT * from accounts where id = ?";
  let imagename = "";
  Account.node.query(query0, [id], (err, currentUser)=>{
    if(err){
      console.log(err)
    }
    if(currentUser){
      currentUser = Object.values(currentUser[0])
      imagename = currentUser[4]
      if(currentUser[2] != email){ // email is changed
      
        query0 = "SELECT * from accounts where email = ?";
        Account.node.query(query0, [email], (err, existingEmail)=>{
   
          if(existingEmail.length > 0){
            console.log("EXISTING:",existingEmail)
            return res.send('<script>alert("Email already in use");window.location.href = "/administration";</script>')
          }
          else{
            let sameimage = false;
      let profphoto;
      //check if image was changed
      if(req.files?.profilephoto){
        profphoto = req.files.profilephoto
        imagename = "images/" + profphoto.name
        // Check if the uploaded file is an image
        const fileMimeType = mime.lookup(profphoto.name);
        if (!fileMimeType || !fileMimeType.startsWith('image/')) {
          fs.unlink(profphoto.tempFilePath, (err) => {
            if (err) {
              //console.error('Failed to delete temporary file:', err);
            } else {
              //console.log('Temporary file deleted');
            }
          });
          return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
        }
    
        // Read the file contents
        console.log(profphoto)
        const fileData = fs.readFileSync(profphoto.tempFilePath);
    
        // Validate the magic number
        const fileTypeResult = fileType(fileData);
        if (!fileTypeResult || !fileTypeResult.mime.startsWith('image/')) {
          fs.unlink(profphoto.tempFilePath, (err) => {
            if (err) {
              //console.error('Failed to delete temporary file:', err);
            } else {
              //console.log('Temporary file deleted');
            }
          });
          return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
        }
      }
      else{ // if image remains the same
        sameimage = true;
        console.log(sameimage)
      }

        //update the details normally
        console.log(sameimage)
          let query = "UPDATE accounts SET email = ?, fullName = ?, phoneNumber = ?, profilePhoto= ? where id = ?";
        
          Account.node.query(query,[email, fullname, phone, imagename, id], (err, result)=>{
            if(err){
              console.log(err);
              return;
            }
            else{
              if(!sameimage){
                const uploadPath = path.join(__dirname, "images", profphoto.name);
                profphoto.mv(uploadPath, (error) => {
                  if (error) {
                    //console.log("failed to save photo")
                    console.log(error);
                  } else {
                    //console.log("ADDED");
                    
                    res.redirect('/administration')
                  }
                });
              }
              else{
                res.redirect('/administration')
              }
              
            }
          })
          }
      
        })
      
     
      }
      else{
        let sameimage = false;
      let profphoto;
      //check if image was changed
      if(req.files?.profilephoto){
        profphoto = req.files.profilephoto
        imagename = "images/" + profphoto.name
        // Check if the uploaded file is an image
        const fileMimeType = mime.lookup(profphoto.name);
        if (!fileMimeType || !fileMimeType.startsWith('image/')) {
          fs.unlink(profphoto.tempFilePath, (err) => {
            if (err) {
              //console.error('Failed to delete temporary file:', err);
            } else {
              //console.log('Temporary file deleted');
            }
          });
          return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
        }
    
        // Read the file contents
        console.log(profphoto)
        const fileData = fs.readFileSync(profphoto.tempFilePath);
    
        // Validate the magic number
        const fileTypeResult = fileType(fileData);
        if (!fileTypeResult || !fileTypeResult.mime.startsWith('image/')) {
          fs.unlink(profphoto.tempFilePath, (err) => {
            if (err) {
              //console.error('Failed to delete temporary file:', err);
            } else {
              //console.log('Temporary file deleted');
            }
          });
          return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
        }
      }
      else{ // if image remains the same
        sameimage = true;
        console.log(sameimage)
      }

        //update the details normally
        console.log(sameimage)
          let query = "UPDATE accounts SET email = ?, fullName = ?, phoneNumber = ?, profilePhoto= ? where id = ?";
        
          Account.node.query(query,[email, fullname, phone, imagename, id], (err, result)=>{
            if(err){
              console.log(err);
              return;
            }
            else{
              if(!sameimage){
                const uploadPath = path.join(__dirname, "images", profphoto.name);
                profphoto.mv(uploadPath, (error) => {
                  if (error) {
                    //console.log("failed to save photo")
                    console.log(error);
                  } else {
                    //console.log("ADDED");
                    
                    res.redirect('/administration')
                  }
                });
              }
              else{
                res.redirect('/administration')
              }
              
            }
          })
      }
      
    }
  })
 
 
});


// Start the server
app.listen(port, () => {
  //console.log(`Server running on port ${port}`);
});
