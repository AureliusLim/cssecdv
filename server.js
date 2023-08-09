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
const e = require('express');
const https = require('https');
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

app.post('/editUser', ensureAuth, async(req, res) => {
  // Input validation using regular expressions
  try{
    let originalemail;
    if(req.session.isAdmin == true){
      originalemail = req.body.originalemail
    }
    else{
      originalemail = req.session.email
    }
  const email = req.body.email;
  let id;
  const fullname = req.body.fullname;
  const phone = req.body.phone;
  console.log(req.body)
  const emailRegex = /^[a-zA-Z0-9]+([_.-][a-zA-Z0-9]+)*@[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z]{2,})+$/;
  const phoneRegex = /^09\d{9}$/;
  if (!emailRegex.test(email)) {
    if(req.session.isAdmin){
      return res.send('<script>alert("Invalid email format"); window.location.href = "/administration";</script>');
    }
    return res.send('<script>alert("Invalid email format"); window.location.href = "/main";</script>');
  }

  if (!phoneRegex.test(phone)) {
    if(req.session.isAdmin){
      return res.send('<script>alert("Invalid phone number"); window.location.href = "/administration";</script>');
    }
    return res.send('<script>alert("Invalid phone number"); window.location.href = "/main";</script>');
  }
  let accquery = "Select * from accounts where email = ?"
  Account.node.query(accquery, [originalemail], (err, obj)=>{
    if(err){
      console.log('account not found')
    }
    else{
      obj = Object.values(obj[0])
      id = obj[0]
          // Check if the email is still the same
      let query0 = "SELECT * from accounts where id = ?";
      let imagename = "";
      Account.node.query(query0, [id], async(err, currentUser)=>{
        if(err){
          console.log(err)
        }
        if(currentUser){
          currentUser = Object.values(currentUser[0])
          imagename = currentUser[4]
          if(currentUser[2] != email){ // email is changed
          
            query0 = "SELECT * from accounts where email = ?";
            Account.node.query(query0, [email], async(err, existingEmail)=>{
      
              if(existingEmail.length > 0){
                console.log("EXISTING:",existingEmail)
                if(req.session.isAdmin){
                  return res.send('<script>alert("Email already in use");window.location.href = "/administration";</script>')
                }
                return res.send('<script>alert("Email already in use");window.location.href = "/main";</script>')
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
                    if(req.session.isAdmin){
                      return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
                    }
                    return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/main";</script>');
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
                    if(req.session.isAdmin){
                      return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
                    }
                    return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/main";</script>');
                  }
                }
                else{ // if image remains the same
                  sameimage = true;
                  console.log(sameimage)
                }

                  //update the details normally
                  console.log(sameimage)
                  if((req.body.pass).length > 0){
                    let query = "UPDATE accounts SET email = ?, fullName = ?, phoneNumber = ?, profilePhoto= ?, password = ? where id = ?";
                    const hashedPassword = await bcrypt.hash(req.body.pass, 10);
                    Account.node.query(query,[email, fullname, phone, imagename, hashedPassword, id], (err, result)=>{
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
                              
                              if(req.session.isAdmin){
                                res.redirect('/administration')
                              }
                              else{
                                req.session.email = email;
                                res.redirect('/main')
                              }
                              
                            }
                          });
                        }
                        else{
                          if(req.session.isAdmin){
                            res.redirect('/administration')
                          }
                          else{
                            req.session.email = email;
                            res.redirect('/main')
                          }
                          
                        }
                        
                      }
                    })
                  }
                  else{
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
                              
                              if(req.session.isAdmin){
                                res.redirect('/administration')
                              }
                              else{
                                req.session.email = email;
                                res.redirect('/main')
                              }
                              
                            }
                          });
                        }
                        else{
                          if(req.session.isAdmin){
                            res.redirect('/administration')
                          }
                          else{
                            req.session.email = email;
                            res.redirect('/main')
                          }
                        
                        }
                        
                      }
                    })
                  }
              
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
                if(req.session.isAdmin){
                  return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
                }
                return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/main";</script>');
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
                if(req.session.isAdmin){
                  return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/administration";</script>');
                }
                return res.send('<script>alert("Invalid file format. Please upload an image file."); window.location.href = "/main";</script>');
              }
            }
            else{ // if image remains the same
              sameimage = true;
              console.log(sameimage)
            }

              //update the details normally
              console.log(sameimage)
              if((req.body.pass).length > 0){
                let query = "UPDATE accounts SET email = ?, fullName = ?, phoneNumber = ?, profilePhoto= ?, password = ? where id = ?";
                const hashedPassword = await bcrypt.hash(req.body.pass, 10);
                Account.node.query(query,[email, fullname, phone, imagename, hashedPassword, id], (err, result)=>{
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
                          
                          if(req.session.isAdmin){
                            res.redirect('/administration')
                          }
                          else{
                            req.session.email = email;
                            res.redirect('/main')
                          }
                          
                        }
                      });
                    }
                    else{
                      if(req.session.isAdmin){
                        res.redirect('/administration')
                      }
                      else{
                        req.session.email = email;
                        res.redirect('/main')
                      }
                      
                    }
                    
                  }
                })
              }
              else{
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
                          
                          if(req.session.isAdmin){
                            res.redirect('/administration')
                          }
                          else{
                            req.session.email = email;
                            res.redirect('/main')
                          }
                          
                        }
                      });
                    }
                    else{
                      if(req.session.isAdmin){
                        res.redirect('/administration')
                      }
                      else{
                        req.session.email = email;
                        res.redirect('/main')
                      }
                      
                    }
                    
                  }
                })
              }
          }
          
        }
      })
    }
  })
  }
  catch{
    console.log('an error occurred')
    return res.send('Please Try Again')
  }
  
 
  
 
 
});

app.post('/deleteUser',ensureAuth, (req, res)=>{
  try{
    const email = req.body.emailToBeDeleted;
    let userId;
    console.log(req.body)
    const userquery = 'Select * from accounts where email = ?';
    Account.node.query(userquery, [email], (err, user)=>{
      if(err){
        return;
      }
      else{
          user = Object.values(user[0]);
          userId = user[0]
          const deletePostsQuery = 'DELETE FROM posts WHERE userid = ?';
          Account.node.query(deletePostsQuery, [userId], (error, results) => {
            if (error) {
              console.error('Error deleting posts:', error);
              return;
            }
            //proceed with deleting user
            let delquery = "Delete from accounts where email = ?"
            Account.node.query(delquery, [email], (err, obj)=>{
              if(err){
                console.log(err)
              }
              else{
                console.log(obj)
                res.redirect('/administration')
              }
            })
        
            });
          
          }
      })
    
  }
  catch{
    
    return res.send('Please Try Again')
  }
  
});
app.get('/getPosts', ensureAuth, (req, res)=>{
  try{
    let postsquery = "SELECT posts.id, posts.content, accounts.fullName AS username FROM posts INNER JOIN accounts ON posts.userid = accounts.id ORDER BY posts.id DESC;"
    Account.node.query(postsquery, (err, posts)=>{
      if (err) {
        console.log(err);
        res.status(500).json({ error: 'Error fetching posts' });
      } else {
        res.status(200).json({ posts });
      }
    })
  }
  catch{
    console.log("error fetching posts");

  }
})

app.post('/submitPost',ensureAuth, (req, res)=>{
  try{
    const author = req.session.email;
    const content = req.body.content;
    let userquery = "Select * from accounts where email = ?";
    let insertquery = "Insert into posts (content, userid) VALUES(?, ?)";
    Account.node.query(userquery, [author], (err, user)=>{
      user = Object.values(user[0])
      if(err){
        return res.send('No User')
      }
      else{
        Account.node.query(insertquery, [content, user[0]], (err, result)=>{
          if(err){
            console.log(err)
            return res.send('Cannot insert')
          }
          else{
            console.log(result)
            if(user[6] == 'admin'){
              res.redirect('/administration')
            }
            else{
              res.redirect('/main')
            }
            
          }
        })
      }
    })
    


  }
  catch{
    return res.send('Please Try Again')
  }
})
// Start the server

const httpsapp = https.createServer(
    {
      key: fs.readFileSync(path.join(__dirname, 'certificate', 'key.pem')), 
      cert: fs.readFileSync(path.join(__dirname, 'certificate', 'certificate.pem'))
    }, 
  app
  );
httpsapp.listen(port);


