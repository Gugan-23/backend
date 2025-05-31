const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
require('dotenv').config();
const multer = require('multer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const FormData = require('form-data');

const PORT = process.env.PORT || 5000;

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all origins

const router = express.Router(); // Initialize the router

// Middleware

app.use(bodyParser.json());
app.use((req, res, next) => {
  res.setTimeout(60000, () => { // Increase to 60 seconds
    console.log('Request timed out');
  });
  next();
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true,useFindAndModify: false, })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  otp: { type: String, default: null }, // Add this field
  otpExpiresAt: { type: Date, default: null }, // Add this field
});

const User = mongoose.model('User', userSchema);
module.exports = User;

// Login Route
app.post('/api/login', async (req, res) => {
  const { usernameOrEmail, password } = req.body;
  
  console.log('Login Request:', req.body); // Log login request data

  try {
    // Check if user exists by username or email
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });

    if (!user) {
      console.warn('Login failed: User not found'); // Log warning
      return res.status(401).send('Invalid credentials: User not found');
    }

    // Directly compare password without hashing
    if (password !== user.password) {
      console.warn('Login failed: Incorrect password'); // Log warning
      return res.status(401).send('Invalid credentials: Incorrect password');
    }

    // Successful login
    console.log('Login successful for user:', user.username);
    return res.status(200).send({ message: 'Login successful', token: 'your_generated_token_here' }); // Send a token or user info if needed

  } catch (error) {
    console.error('Server error during login:', error.message); // Log server error
    res.status(500).send('Server error: ' + error.message);
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASS  // Your email password or app password
  }
});

// Forgot Password Endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Set OTP expiration time (e.g., 10 minutes)
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Save OTP and expiration time to the user's record
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    // Send the OTP via email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your Password Reset OTP',
      html: `
        <h1>Password Reset OTP</h1>
        <p>Your One-Time Password (OTP) is:</p>
        <h2>${otp}</h2>
        <p>This OTP will expire in 10 minutes.</p>
      `
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ message: 'Failed to send OTP' });
      }
      console.log('OTP email sent:', info.response);
      res.json({ message: 'OTP sent to your email' });
    });
  } catch (error) {
    console.error('Error in forgot password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  // Validate request body
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required.' });
  }

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    console.log('Fetched User:', user); // Debugging: Check fetched user

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Check if OTP is set for the user
    if (!user.otp) {
      console.log('User OTP not set:', user.otp); // Debugging: Check OTP field
      return res
        .status(400)
        .json({ message: 'No OTP found for this user. Please request a new OTP.' });
    }

    // Compare provided OTP with stored OTP
    if (user.otp.toString() !== otp.toString()) {
      console.log(`Invalid OTP. Provided: ${otp}, Stored: ${user.otp}`); // Debugging
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    // Check if the OTP has expired
    if (new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new OTP.' });
    }

    // OTP is valid, clear it from the database
    user.otp = null;
    user.otpExpiresAt = null;
    await user.save();

    res.json({ message: 'OTP verified successfully.' });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // Find user in database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Save updated user to the database
    await user.save();
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});


const otpSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  otp: Number,
  createdAt: { type: Date, default: Date.now, expires: 600 },
});
const OTP = mongoose.model('OTP', otpSchema);
const transporter1 = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'h8702643@gmail.com', // Your email address
    pass: 'osxarglpzcircimn' // Use App Password instead of your Google account password
  },
  tls: {
    rejectUnauthorized: false // Disable unauthorized rejection for certain connections
  }
});

// Endpoint: Send OTP
app.post('/api/send-otp1', async (req, res) => {
try {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  const otp = Math.floor(50000 + Math.random() * 900000); // Generate 6-digit OTP

  // Save OTP in one atomic operation
  await OTP.findOneAndUpdate(
    { email },
    { otp, createdAt: new Date() },
    { upsert: true, new: true }
  );

  // Send OTP via email using transporter1
  await transporter1.sendMail({
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
  });

  res.json({ message: 'OTP sent successfully' });
} catch (error) {
  console.error('Error sending OTP:', error);
  res.status(500).json({ message: 'Error sending OTP' });
}
});

// Endpoint: Verify Signup
app.post('/api/verify-signup', async (req, res) => {
  try {
    const { username, email, password, otp } = req.body;

    if (!username || !email || !password || !otp)
      return res.status(400).json({ message: 'All fields are required' });

    // Validate OTP
    const otpRecord = await OTP.findOne({ email });
    if (!otpRecord || otpRecord.otp !== parseInt(otp))
      return res.status(400).json({ message: 'Invalid OTP' });

    // Save new user
    const user = new User({ username, email, password });
    await user.save();
    console.log('New User:', user);

    // Delete OTP after success
    await OTP.deleteOne({ email });

    res.json({ message: 'Signup successful' });
  } catch (error) {
    console.error('Error during signup:', error);
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      res.status(400).json({ message: 'Email already registered' });
    } else {
      res.status(500).json({ message: 'Error during signup' });
    }
  }
});
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
    if (users.length === 0) {
      return res.status(404).send({ message: 'No users found' });
    }
    res.status(200).send({
      message: 'Users fetched successfully',
      users: users.map(user => ({
        id: user._id,
        username: user.username,
        email: user.email,
      })),
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send({ message: 'Error fetching users', error: err.message });
  }
});
// Get All Users Route
// Get All Users Route
// Delete User Route
const deletedUserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  deletedAt: { type: Date, default: Date.now },
});

const DeletedUser = mongoose.model('DeletedUser', deletedUserSchema);

app.delete('/api/users/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    // Step 1: Find the user to delete
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    // Step 2: Store the user in the deleted users collection (allow duplicates)
    const deletedUser = {
      username: user.username,
      email: user.email,
      password: user.password, // Be cautious when storing passwords; in a real system, you'd want to hash it first
      deletedAt: new Date(),
    };

    // Use findOneAndUpdate to allow duplicates and upsert the record
    await DeletedUser.findOneAndUpdate(
      { email: user.email }, // Match on email to handle duplicates
      deletedUser, // Update the user data
      { upsert: true, new: true } // Create if it doesn't exist
    );

    // Step 3: Delete the user from the User collection
    await User.findByIdAndDelete(userId);

    res.status(200).send({ message: 'User deleted and stored in the deleted users collection' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send({ message: 'Failed to delete user', error: err.message });
  }
});
const API_KEY = process.env.IMGBB_API_KEY;

// Define the event schema with event_location
const eventSchema = new mongoose.Schema({
  event_name: String,
  description: String,
  event_time: Date,
  event_speaker:String,
  event_location: String, // Added event_location field
  image_url: String
});
const Event = mongoose.model('Event12', eventSchema);

// Multer setup for image uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Upload image to ImgBB
async function uploadImageToImgBB(imageBuffer) {
  const formData = new FormData();
  formData.append('image', imageBuffer.toString('base64'));

  try {
      const response = await axios.post(`https://api.imgbb.com/1/upload?key=${API_KEY}`, formData, {
          headers: formData.getHeaders(),
      });
      
      if (response.data && response.data.data && response.data.data.url) {
          console.log("Image uploaded successfully:", response.data.data.url);
          return response.data.data.url;
      } else {
          console.error("ImgBB response missing data:", response.data);
          return null;
      }
  } catch (error) {
      console.error("Error uploading image:", error);
      return null;
  }
}

// API route to handle uploads
app.post('/upload', upload.single('image'), async (req, res) => {
  const { event_name, description,event_speaker, event_time, event_location } = req.body;
  const image = req.file;

  try {
      // Check if image is provided
      if (!image) {
          console.error("No image file provided");
          return res.status(400).json({ error: "No image file provided" });
      }
      
      // Debugging log to ensure image buffer exists
      console.log("Image buffer received:", image.buffer);

      // Attempt to upload the image and get the URL
      const imageUrl = await uploadImageToImgBB(image.buffer);

      if (!imageUrl) {
          console.error("Image URL generation failed");
          return res.status(500).json({ error: "Failed to upload image to ImgBB" });
      }

      // Create and save new event with image URL and event_location
      const newEvent = new Event({
          event_name,
          description,
          event_speaker,
          event_time,
          event_location, // Add event_location to the new event
          image_url: imageUrl
      });

      await newEvent.save();
      console.log("Event uploaded successfully:", newEvent);
      res.status(201).json({ message: "Event uploaded successfully", event: newEvent, imageUrl });
  } catch (error) {
      console.error("Error saving event:", error);
      res.status(500).json({ error: "Failed to upload event" });
  }
});

// API route to get all events
app.get('/api/events', async (req, res) => {
  try {
      const events = await Event.find();
      if (events.length === 0) {
          return res.status(404).send({ message: 'No events found' });
      }
      res.status(200).send({ message: 'Events fetched successfully', events });
  } catch (err) {
      console.error('Error fetching events:', err);
      res.status(500).send({ message: 'Error fetching events', error: err.message });
  }
});

// API route to delete an event by ID
app.delete('/api/events/:id', async (req, res) => {
  const { id } = req.params;
  console.log("Event ID to delete:", id);

  // Validate the ID format (assuming MongoDB's 24-character hexadecimal format)
  if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      return res.status(400).send({ message: 'Invalid event ID format' });
  }

  try {
      // Attempt to find and delete the event by its ID
      const deletedEvent = await Event.findByIdAndDelete(id);

      if (!deletedEvent) {
          // If no event is found with the given ID, return a 404 status
          return res.status(404).send({ message: 'Event not found' });
      }

      // Return a success message and the deleted event data
      res.status(200).send({ message: 'Event deleted successfully', event: deletedEvent });
  } catch (err) {
      // Handle any unexpected errors during deletion
      console.error('Error deleting event:', err);
      res.status(500).send({ message: 'Error deleting event', error: err.message });
  }
});

async function uploadImageToImgBB(imageBuffer) {
  const formData = new FormData();
  formData.append('image', imageBuffer.toString('base64'));

  try {
    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${API_KEY}`,
      formData,
      { headers: formData.getHeaders() }
    );

    if (response.data && response.data.data && response.data.data.url) {
      console.log('Image uploaded successfully:', response.data.data.url);
      return response.data.data.url;
    } else {
      console.error('ImgBB response missing data:', response.data);
      return null;
    }
  } catch (error) {
    console.error('Error uploading image:', error);
    return null;
  }
}
const imageSchema = new mongoose.Schema({
  contentType: String,
  url: String, // Store the ImgBB URL here
});

const Image = mongoose.model('Image1', imageSchema);

module.exports = Image;
// API endpoint to handle image upload
app.post('/upload2', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Upload the image to ImgBB
    const imageUrl = await uploadImageToImgBB(req.file.buffer);
    
    if (!imageUrl) {
      return res.status(500).json({ error: 'Failed to upload image to ImgBB' });
    }

    // Save only the URL and content type to MongoDB
    const newImage = new Image({
      contentType: req.file.mimetype,
      url: imageUrl, // Save ImgBB URL in the database
    });

    await newImage.save();

    // Return the image URL immediately after upload
    res.status(200).json({
      message: 'Image uploaded successfully',
      imageUrl: imageUrl, // Directly return the uploaded image URL
    });
  } catch (error) {
    console.error('Error handling upload:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});
// Endpoint to refresh image data
app.post('/refresh-images', async (req, res) => {
  try {
    console.log("Refreshing image data...");
    
    // Add your logic to refresh the image data here
    // For example, synchronizing data from external sources, cleaning up old images, etc.
    // If no specific refresh logic is required, you can skip this step.
    // Simulating a refresh process
    await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate a delay for the refresh

    console.log("Image data refreshed successfully");
    res.status(200).json({ message: 'Image data refreshed successfully' });
  } catch (err) {
    console.error("Error refreshing image data:", err);
    res.status(500).json({ error: 'Failed to refresh image data' });
  }
});

// Endpoint to fetch image URLs
app.get('/images1', async (req, res) => {
  try {
    const images = await Image.find()
      .sort({ _id: -1 }) // Sort by most recent
      .limit(10)         // Limit to 10 records
      .lean();           // Use lean query for faster data retrieval

    const imageUrls = images.map(image => image.url);

    res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache images for a year
    res.json(imageUrls);
    console.log("Images fetched successfully");
  } catch (err) {
    console.error("Error fetching images:", err);
    res.status(500).json({ error: 'Failed to fetch images' });
  }
});






app.put('/api/events/:id', async (req, res) => {
  const { id } = req.params;
  console.log("Event update :", id);
  const updatedData = req.body;

  try {
    const event = await Event.findByIdAndUpdate(id, updatedData, { new: true });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(200).json(event);
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ error: 'Failed to update event' });
  }
});
app.get('/api/events/:id', async (req, res) => {
  const { id } = req.params;
  console.log("Event :", id);
  try {
    const event = await Event.findById(id);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(200).json(event);
  } catch (error) {
    console.error('Error fetching event:', error);
    res.status(500).json({ error: 'Failed to fetch event' });
  }
});

// Add a createdAt field to the schema with a default value of the current date
const userRoleSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, required: true },
  department: { type: String, required: true },
  linkedinlink:{type: String, required: true },
  image_url: { type: String, required: true },
  createdAt: String, // String to match your data format
});

const UserRole = mongoose.model('UserRole1', userRoleSchema); // Ensure the collection name matches

// API to fetch distinct year ranges
app.get('/api/yearRanges', async (req, res) => {
  try {
    // Fetch distinct values of createdAt from the UserRole1 collection
    const yearRanges = await UserRole.distinct('createdAt');
    console.log('Year ranges fetched successfully:', yearRanges);
    res.status(200).json({ message: 'Year ranges fetched successfully', yearRanges });
  } catch (error) {
    console.error('Error fetching year ranges:', error);
    res.status(500).json({ message: 'Failed to fetch year ranges' });
  }
});
app.get('/api/userRoles1', async (req, res) => {
  try {
    const { createdAt } = req.query;

    if (!createdAt) {
      return res.status(400).json({ message: 'Year range is required' });
    }

    // Fetch users for the selected year range
    const users = await UserRole.find({ createdAt });

    if (users.length === 0) {
      return res.status(404).json({ message: 'No users found for the given year range' });
    }

    res.status(200).json({ message: 'Users fetched successfully', users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// Upload image to ImgBB
async function uploadImageToImgBB(imageBuffer) {
  const formData = new FormData();
  formData.append('image', imageBuffer.toString('base64'));

  try {
      const response = await axios.post(`https://api.imgbb.com/1/upload?key=${API_KEY}`, formData, {
          headers: formData.getHeaders(),
      });

      if (response.data && response.data.data && response.data.data.url) {
          console.log("Image uploaded successfully:", response.data.data.url);
          return response.data.data.url;
      } else {
          console.error("ImgBB response missing data:", response.data);
          return null;
      }
  } catch (error) {
      console.error("Error uploading image:", error);
      return null;
  }
}

// API route to handle uploads
app.post('/upload1', upload.single('image'), async (req, res) => {
  const { name, email, role, department,linkedinlink, createdAt } = req.body; // Include createdAt input
  const image = req.file;

  // Validate required fields
  if (!name || !email || !role || !department || !linkedinlink || !createdAt) { // Check for createdAt
      return res.status(400).json({ error: "name, email, role, department, and createdAt are required." });
  }

  // Validate the academic year format (YYYY-YYYY)
  if (!name || !email || !role || !department || !linkedinlink || !createdAt) {
    return res.status(400).json({ error: "name, email, role, department, and createdAt are required." });
  }

  const academicYearPattern = /^\d{4}-\d{4}$/;
  if (!academicYearPattern.test(createdAt)) {
    return res.status(400).json({ error: "Invalid academic year format. Use 'YYYY-YYYY'." });
  }

  if (!image) {
      console.error("No image file provided");
      return res.status(400).json({ error: "No image file provided" });
  }

  try {
      // Attempt to upload the image and get the URL
      const imageUrl = await uploadImageToImgBB(image.buffer);

      if (!imageUrl) {
          console.error("Image URL generation failed");
          return res.status(500).json({ error: "Failed to upload image to ImgBB" });
      }

      // Create and save new UserRole with image URL
      const newUserRole = new UserRole({
          name,
          email,
          role,
          department,
          linkedinlink,
          image_url: imageUrl,
          createdAt // Save user-provided academic year
      });

      await newUserRole.save();
      console.log("UserRole uploaded successfully:", newUserRole);
      res.status(201).json({ message: "UserRole uploaded successfully", UserRole: newUserRole });
  } catch (error) {
      console.error("Error saving UserRole:", error);
      res.status(500).json({ error: "Failed to upload UserRole" });
  }
});

// Node.js Express route to filter users by a specified year range
app.get('/api/userRoles', async (req, res) => {
  const { startYear, endYear } = req.query;

  const filter = {};
  if (startYear && endYear) {
    filter.createdAt = {
      $gte: new Date(`${startYear}-01-01`),
      $lt: new Date(`${endYear}-12-31`),
    };
  }

  try {
    const userRoles = await UserRole.find(filter);
    res.status(200).json({ message: 'User roles fetched successfully', userRoles });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user roles', error: error.message });
  }
});

app.delete('/api/userRoles/:id', async (req, res) => {
  const { id } = req.params; // Get user ID from request parameters

  try {
    const deletedUserRole = await UserRole.findByIdAndDelete(id); // Delete user role from the database

    if (!deletedUserRole) {
      return res.status(404).send({ message: 'User role not found' }); // If not found, send a 404 error
    }

    console.log('User role deleted successfully');
    res.status(200).send({ message: 'User role deleted successfully', userRole: deletedUserRole });
  } catch (error) {
    console.error('Error deleting user role:', error.message); // Log the error for debugging
    res.status(500).send({ message: 'Error deleting user role', error: error.message });
  }
});
app.get('/api/userRoles/yearRange/:year', async (req, res) => {
  const { year } = req.params;

  // Validate year format
  const academicYearPattern = /^\d{4}-\d{4}$/;
  if (!academicYearPattern.test(year)) {
    return res.status(400).json({ error: "Invalid academic year format. Use 'YYYY-YYYY'." });
  }

  try {
    // Fetch users matching the academic year
    const users = await UserRole.find({ createdAt: year });
    res.status(200).json({ message: "Users fetched successfully", users });
  } catch (error) {
    console.error("Error fetching users by year range:", error);
    res.status(500).json({ error: "Failed to fetch users by year range" });
  }
});
const roleSchema = new mongoose.Schema({
  roleName: { type: String, required: true },
  rank: { type: Number, required: true }
});

const RoleModel = mongoose.model('Role', roleSchema);

// API Endpoint to add a new role with rank
app.post('/api/addNewRole', async (req, res) => {
  try {
    const { role, rank } = req.body;

    // Create a new role document
    const newRole = await RoleModel.create({
      roleName: role,
      rank: rank
    });
    console.log('Role added',newRole );
    res.status(200).json({ message: 'Role added successfully', role: newRole });

  } catch (err) {
    console.error('Failed to add new role:', err);
    res.status(500).json({ message: 'Failed to add role', error: err.message });
  }
});
// Endpoint to fetch unique year ranges
app.get('/api/getRoles', async (req, res) => {
  try {
    // Fetch all roles from the database
    const roles = await RoleModel.find({});
    console.log('Roles fetched:', roles);
    res.status(200).json({ message: 'Roles fetched successfully', roles });
  } catch (err) {
    console.error('Failed to fetch roles:', err);
    res.status(500).json({ message: 'Failed to fetch roles', error: err.message });
  }
});


const closeSchema = new mongoose.Schema({
  year: { type: String, required: true },           // Year range as a string, e.g., "2023-2022"
  hidden: { type: Boolean, required: true },         // Whether the delete button is hidden
  showToggleDelete: { type: Boolean, default: true }, // Controls visibility of the Toggle Delete button
  timestamp: { type: Date, default: Date.now },      // Timestamp for when the action was taken
});

const Close = mongoose.model('Close', closeSchema);


app.post('/api/userRoles/hideYear', async (req, res) => {
  const { year, hidden } = req.body;

  try {
    await Close.findOneAndUpdate(
      { year },
      { hidden, timestamp: new Date() },
      { upsert: true } // Insert if it doesn't exist
    );
    console.log('Closed successfully');
    res.json({ message: 'Year visibility saved successfully in Close collection' });
  } catch (error) {
    console.log('Failed to close');
    res.status(500).json({ message: 'Failed to save year visibility', error });
  }
});
app.post('/api/userRoles/hideToggleDelete', async (req, res) => {
  const { year } = req.body;

  try {
    // Update or insert a record for the year, setting `showToggleDelete` to false
    await Close.findOneAndUpdate(
      { year },
      { showToggleDelete: false, hidden: true },
      { upsert: true, new: true }
    );

    res.json({ message: 'Toggle Delete visibility updated successfully' });
  } catch (error) {
    console.error('Failed to update visibility:', error);
    res.status(500).json({ message: 'Failed to update visibility', error });
  }
});

app.get('/api/userRoles/hiddenYears', async (req, res) => {
  try {
    const hiddenYears = await Close.find({ hidden: true }, 'year hidden').exec();
    res.json(hiddenYears);
  } catch (error) {
    console.log('Failed to fetch hidden years');
    res.status(500).json({ message: 'Failed to retrieve hidden years', error });
  }
});
require('dotenv').config(); // load .env variables FIRST
const cloudinary = require('cloudinary').v2;

const fs = require('fs');
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload4 = multer({ dest: 'uploads/' });

const productSchema = new mongoose.Schema({
  
  name: String,
  specifications: [
    {
      type: { type: String},
      detail: { type: String}
    }
  ],
  category: String,
  images: [String]
});

const Product = mongoose.model('Product1', productSchema);

// Accept any number of photos
app.get('/categories', async (req, res) => {
  try {
    // Get distinct category values from the 'products' collection
    const categories = await Product.distinct('category');
    res.json(categories);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch categories' });
  }
});


app.post('/upload-product', upload4.array('photos'), async (req, res) => {
  const { name, specifications, category } = req.body;

  if (!name || !specifications || !category) {
    return res.status(400).json({ error: 'Missing name, specifications, or category' });
  }

  let specsArray;
  try {
    specsArray = JSON.parse(specifications); // parse JSON string
  } catch (e) {
    return res.status(400).json({ error: 'Invalid specifications format' });
  }

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'At least 1 photo is required' });
  }

  try {
    const uploadedUrls = [];

    for (const file of req.files) {
      const result = await cloudinary.uploader.upload(file.path);
      fs.unlinkSync(file.path);

      if (result.secure_url) {
        console.log(result.secure_url);

        uploadedUrls.push(result.secure_url);
        console.log(uploadedUrls);
      } else {
        return res.status(500).json({ error: 'Cloudinary upload failed' });
      }
    }

    const productData = new Product({
      name,
      specifications: specsArray,
      category,
      images: uploadedUrls,
    });

    const savedProduct = await productData.save();
    console.log(productData);
    return res.status(200).json({
      message: 'Product uploaded and saved successfully',
      product: savedProduct,
    });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find(); // Fetch all products
    res.status(200).json(products);
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.delete('/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Product.findByIdAndDelete(id);

    if (!deleted) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
const careerSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
  },
  username: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    match: [/^[0-9]{10}$/, 'Phone number must be 10 digits']
  },
  city: {
    type: String,
    required: true,
    trim: true
  },
  state: {
    type: String,
    required: true,
    trim: true
  },
  resumeUrl: {
    type: String,
    required: false, // Make true if resume is mandatory
    trim: true
  }
}, {
  timestamps: true
});

const upload6 = multer({ dest: 'uploads/' });


const Career = mongoose.model('Career', careerSchema);

app.post('/career', upload6.single('resume'), async (req, res) => {
  try {
    const { email, username, phone, city, state } = req.body;

    let resumeUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path);
      resumeUrl = result.secure_url;
      fs.unlinkSync(req.file.path); // Clean up local file
    }

    const career = new Career({
      email,
      username,
      phone,
      city,
      state,
      resumeUrl // Add this field in your schema if you haven't
    });

    await career.save();
    console.log("Cared submittes");
        res.status(201).json({ message: "Career form submitted successfully", data: career });
  } catch (err) {
    res.status(400).json({ message: "Failed to submit", error: err.message });
  }
});
app.get('/career', async (req, res) => {
  try {
    const careers = await Career.find();
    res.status(200).json(careers);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch careers", error: err.message });
  }
});
app.get('/products/:id', async (req, res) => {
  const productId = req.params.id;

  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).send({ error: 'Product not found' });
    }
    res.json(product);
  } catch (err) {
    res.status(500).send({ error: 'Server error' });
  }
});
const uploadEdit = multer({ storage: storage });
app.put('/products/:id', uploadEdit.array('newImages'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, category, specifications, existingImages } = req.body;
    
    console.log('Request Body:', req.body);
    console.log('Uploaded Files:', req.files);
    const parsedSpecs = JSON.parse(specifications || '[]');
    const parsedExistingImages = JSON.parse(existingImages || '[]');

    const newUploadedUrls = [];

    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        // Convert buffer to base64 for Cloudinary upload
        const base64Image = file.buffer.toString('base64');
        const result = await cloudinary.uploader.upload(`data:${file.mimetype};base64,${base64Image}`);
        console.log(result);
        
        if (result.secure_url) newUploadedUrls.push(result.secure_url);
      }
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      {
        name,
        category,
        specifications: parsedSpecs,
        images: [...parsedExistingImages, ...newUploadedUrls],
      },
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.status(200).json({ message: 'Product updated successfully', product: updatedProduct });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});
app.get('/products1', async (req, res) => { 
  const category = req.query.category;

  try {
    const products = await Product.find({ category: category }); // strict match
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).send('Server error');
  }
});

const EMAIL_USER = 'h8702643@gmail.com';
const EMAIL_PASS = 'osxarglpzcircimn';
// Endpoint to handle form submission
app.post('/send', async (req, res) => {
  const { name, email, message } = req.body;

  try {
    // Send confirmation email to user
    await transporter.sendMail({
      from: `"Support" <${EMAIL_USER}>`,
      to: email,
      subject: 'Message Successfully Received',
      html: `<p>Dear ${name},</p><p>Your message has been successfully received. We'll get back to you shortly.</p><p>Thank you!</p>`,
    });

    // Send email to admin
    await transporter.sendMail({
      from: `"Contact Form" <${EMAIL_USER}>`,
      to: 'v.gugan16@gmail.com',
      subject: 'New Contact Form Submission',
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong><br/>${message}</p>
      `,
    });

    res.status(200).json({ message: 'Emails sent successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to send emails.' });
  }
});
// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
