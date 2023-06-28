const express = require('express');
const mongoose = require('mongoose');
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://aureliuslim2:KXHGXFVVPC5LAOsm@cluster0.qmyar.mongodb.net/?retryWrites=true&w=majority";
const fileUpload = require('express-fileupload');
const bcrypt = require('bcrypt');
const Account = require('./model/accountSchema');
const path = require('path');
const app = express();
const port = 4000;

// Set up the 'hbs' view engine
app.set('view engine', 'hbs');
app.use(express.static(__dirname));
app.use(express.json());
app.use(fileUpload());
app.set('views', './frontend');
mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define a route for '/register' to render the registration template
app.get('/', (req, res) => {
  res.render('login.hbs');
});
// Handle the login form submission
app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
  
    try {
      // Find the user by email
      const user = await Account.findOne({ email : email });
        console.log(email)
      if (user) {
        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
  
        if (isMatch) {
          // Passwords match, user is authenticated
          res.render('main.hbs');
          //res.send('Login successful');
        } else {
          // Passwords do not match
          res.send('Invalid credentials');
        }
      } else {
        // User not found
        res.send('invalid credentials');
      }
    } catch (err) {
      console.log(err);
      res.send('Error occurred');
    }
  });

// Logout Function
app.get('/logout', (req, res) => {
  res.render('login.hbs');
});

// Administration Function
app.get('/administration', async (req, res) => {
  const users = await Account.find({});
  console.log(users)
  res.render('administration', {
    users: users
  })
})

// Direct to registration hbs
app.get('/register', (req, res) => {
  res.render('registration.hbs');
});

app.post('/registerdetails', async (req, res) => {
  const profphoto = req.files.profilephoto;
  const fullname = req.body.fullname;
  const email = req.body.email;
  const phone = req.body.phone;
  const password = req.body.password;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const account = await Account.create({
      fullName: fullname,
      email: email,
      phoneNumber: phone,
      profilePhoto: "images/" + profphoto.name,
      password: hashedPassword // Store the hashed password in the database
    });

    const uploadPath = path.join(__dirname, 'images', profphoto.name);
    profphoto.mv(uploadPath, (error) => {
      if (error) {
        console.log(error);
      } else {
        console.log("ADDED");
        console.log(account);
        res.render('login.hbs')
      }
    });
  } catch (err) {
    console.log(err);
  }
});


// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
