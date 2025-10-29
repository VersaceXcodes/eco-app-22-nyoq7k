import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';
import { Pool } from 'pg';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import morgan from 'morgan';
import { z } from 'zod';

dotenv.config();

// ESM workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Zod Schemas for validation
const userSchema = z.object({
  user_id: z.string(),
  full_name: z.string(),
  email: z.string().email(),
  created_at: z.string(),
  is_verified: z.boolean().optional(),
  profile_picture_url: z.string().optional()
});

const registerInputSchema = z.object({
  full_name: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(6)
});

const loginInputSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const villaSchema = z.object({
  villa_id: z.string(),
  title: z.string(),
  description: z.string(),
  location: z.string(),
  price_per_night: z.number(),
  amenities: z.array(z.string()),
  photos: z.array(z.object({
    photo_id: z.string(),
    url: z.string(),
    is_primary: z.boolean()
  })),
  host_user_id: z.string(),
  created_at: z.string()
});

const wishlistItemSchema = z.object({
  wishlist_item_id: z.string(),
  user_id: z.string(),
  villa_id: z.string(),
  added_at: z.string(),
  villa: villaSchema.optional()
});

const addWishlistInputSchema = z.object({
  villa_id: z.string()
});

const inquirySchema = z.object({
  inquiry_id: z.string(),
  user_id: z.string(),
  villa_id: z.string(),
  message: z.string(),
  created_at: z.string(),
  is_read: z.boolean()
});

const createInquiryInputSchema = z.object({
  user_id: z.string(),
  villa_id: z.string(),
  message: z.string().min(1)
});

const updatePhotosInputSchema = z.array(z.object({
  photo_id: z.string(),
  url: z.string(),
  is_primary: z.boolean()
}));

// Error response utility
interface ErrorResponse {
  success: false;
  message: string;
  error_code?: string;
  details?: any;
  timestamp: string;
}

function createErrorResponse(
  message: string,
  error?: any,
  errorCode?: string
): ErrorResponse {
  const response: ErrorResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (errorCode) {
    response.error_code = errorCode;
  }

  if (error) {
    response.details = {
      name: error.name,
      message: error.message,
      stack: error.stack
    };
  }

  return response;
}

// Database configuration
const { DATABASE_URL, PGHOST, PGDATABASE, PGUSER, PGPASSWORD, PGPORT = 5432, JWT_SECRET = 'your-secret-key' } = process.env;

const pool = new Pool(
  DATABASE_URL
    ? { 
        connectionString: DATABASE_URL, 
        ssl: { require: true } 
      }
    : {
        host: PGHOST,
        database: PGDATABASE,
        user: PGUSER,
        password: PGPASSWORD,
        port: Number(PGPORT),
        ssl: { require: true },
      }
);

const app = express();
const port = process.env.PORT || 3000;

// Middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json({ limit: "5mb" }));
app.use(morgan('combined'));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Create storage directory if it doesn't exist
const storageDir = path.join(__dirname, 'storage');
if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, storageDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

/*
  Authentication middleware for protected routes
  Validates JWT token and fetches user data from database
*/
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json(createErrorResponse('Access token required', null, 'AUTH_TOKEN_MISSING'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT user_id, full_name, email, created_at, is_verified, profile_picture_url FROM users WHERE user_id = $1', [decoded.user_id]);
    
    if (result.rows.length === 0) {
      return res.status(401).json(createErrorResponse('Invalid token', null, 'AUTH_TOKEN_INVALID'));
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json(createErrorResponse('Invalid or expired token', error, 'AUTH_TOKEN_INVALID'));
  }
};

/*
  Helper function to generate unique IDs
  Creates UUID-like strings for database primary keys
*/
function generateId() {
  return 'id_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// AUTH ROUTES

/*
  POST /api/auth/register
  Registers a new user with full_name, email, and password
  Returns JWT token and user data upon successful registration
*/
app.post('/api/auth/register', async (req, res) => {
  try {
    const validatedData = registerInputSchema.parse(req.body);
    const { full_name, email, password } = validatedData;

    // Check if user already exists
    const existingUser = await pool.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json(createErrorResponse('User with this email already exists', null, 'USER_ALREADY_EXISTS'));
    }

    // Create new user (no password hashing for development)
    const user_id = generateId();
    const result = await pool.query(
      'INSERT INTO users (user_id, full_name, email, password_hash, created_at, is_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id, full_name, email, created_at, is_verified',
      [user_id, full_name.trim(), email.toLowerCase().trim(), password, new Date().toISOString(), false]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      access_token: token,
      token_type: 'Bearer',
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      user: user
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Registration error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  POST /api/auth/login
  Authenticates user with email and password
  Returns JWT token and user data upon successful login
*/
app.post('/api/auth/login', async (req, res) => {
  try {
    const validatedData = loginInputSchema.parse(req.body);
    const { email, password } = validatedData;

    // Find user and validate password (direct comparison for development)
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (result.rows.length === 0) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    const user = result.rows[0];

    // Check password (direct comparison for development)
    if (password !== user.password_hash) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    // Generate JWT token
    const token = jwt.sign(
      { user_id: user.user_id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        created_at: user.created_at,
        is_verified: user.is_verified,
        profile_picture_url: user.profile_picture_url
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Login error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// USER ROUTES

/*
  GET /api/users/{user_id}
  Retrieves public profile data for a specific user
  Returns user information including profile picture
*/
app.get('/api/users/:user_id', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.params;

    const result = await pool.query(
      'SELECT user_id, full_name, email, created_at, is_verified, profile_picture_url FROM users WHERE user_id = $1', 
      [user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('User not found', null, 'USER_NOT_FOUND'));
    }

    const user = result.rows[0];
    const validatedUser = userSchema.parse(user);

    res.json(validatedUser);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// VILLA ROUTES

/*
  GET /api/villas
  Searches for villas with optional filters (location, dates, guests, amenities, price range)
  Returns array of villa listings matching the search criteria
*/
app.get('/api/villas', async (req, res) => {
  try {
    const { location, check_in, check_out, guests, amenities, price_min, price_max } = req.query;

    let query = `
      SELECT v.villa_id, v.title, v.description, v.location, v.price_per_night, 
             v.amenities, v.photos, v.host_user_id, v.created_at
      FROM villas v
      WHERE 1=1
    `;
    const queryParams = [];
    let paramCount = 0;

    // Apply filters
    if (location) {
      paramCount++;
      query += ` AND LOWER(v.location) LIKE LOWER($${paramCount})`;
      queryParams.push(`%${location}%`);
    }

    if (price_min) {
      paramCount++;
      query += ` AND v.price_per_night >= $${paramCount}`;
      queryParams.push(parseInt(price_min));
    }

    if (price_max) {
      paramCount++;
      query += ` AND v.price_per_night <= $${paramCount}`;
      queryParams.push(parseInt(price_max));
    }

    if (amenities) {
      const amenityList = Array.isArray(amenities) ? amenities : [amenities];
      for (const amenity of amenityList) {
        paramCount++;
        query += ` AND $${paramCount} = ANY(v.amenities)`;
        queryParams.push(amenity);
      }
    }

    query += ' ORDER BY v.created_at DESC';

    const result = await pool.query(query, queryParams);
    
    // Transform results to match schema
    const villas = result.rows.map(villa => ({
      ...villa,
      amenities: villa.amenities || [],
      photos: villa.photos || []
    }));

    res.json(villas);
  } catch (error) {
    console.error('Search villas error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  PATCH /api/villas/{villa_id}/photos
  Updates the photos for a specific villa (host only)
  Validates that user is the villa host before allowing updates
*/
app.patch('/api/villas/:villa_id/photos', authenticateToken, async (req, res) => {
  try {
    const { villa_id } = req.params;
    const validatedPhotos = updatePhotosInputSchema.parse(req.body);

    // Check if user is the villa host
    const villaResult = await pool.query('SELECT host_user_id FROM villas WHERE villa_id = $1', [villa_id]);
    if (villaResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Villa not found', null, 'VILLA_NOT_FOUND'));
    }

    if (villaResult.rows[0].host_user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Not authorized to update this villa', null, 'AUTHORIZATION_ERROR'));
    }

    // Ensure only one primary photo
    const primaryPhotos = validatedPhotos.filter(photo => photo.is_primary);
    if (primaryPhotos.length !== 1) {
      return res.status(400).json(createErrorResponse('Exactly one photo must be marked as primary', null, 'INVALID_PRIMARY_PHOTO'));
    }

    // Update villa photos
    const updateResult = await pool.query(
      'UPDATE villas SET photos = $1 WHERE villa_id = $2 RETURNING *',
      [JSON.stringify(validatedPhotos), villa_id]
    );

    const updatedVilla = updateResult.rows[0];
    updatedVilla.photos = validatedPhotos;

    res.json(updatedVilla);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid photo data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Update villa photos error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// WISHLIST ROUTES

/*
  GET /api/wishlists
  Fetches all wishlist items for the authenticated user
  Includes villa details for each wishlist item
*/
app.get('/api/wishlists', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT w.wishlist_item_id, w.user_id, w.villa_id, w.added_at,
             v.title, v.description, v.location, v.price_per_night, 
             v.amenities, v.photos, v.host_user_id, v.created_at as villa_created_at
      FROM wishlist_items w
      JOIN villas v ON w.villa_id = v.villa_id
      WHERE w.user_id = $1
      ORDER BY w.added_at DESC
    `;

    const result = await pool.query(query, [req.user.user_id]);

    const wishlistItems = result.rows.map(row => ({
      wishlist_item_id: row.wishlist_item_id,
      user_id: row.user_id,
      villa_id: row.villa_id,
      added_at: row.added_at,
      villa: {
        villa_id: row.villa_id,
        title: row.title,
        description: row.description,
        location: row.location,
        price_per_night: row.price_per_night,
        amenities: row.amenities || [],
        photos: row.photos || [],
        host_user_id: row.host_user_id,
        created_at: row.villa_created_at
      }
    }));

    res.json(wishlistItems);
  } catch (error) {
    console.error('Get wishlist error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  POST /api/wishlists
  Adds a villa to the authenticated user's wishlist
  Prevents duplicate entries for the same user and villa
*/
app.post('/api/wishlists', authenticateToken, async (req, res) => {
  try {
    const validatedData = addWishlistInputSchema.parse(req.body);
    const { villa_id } = validatedData;

    // Check if villa exists
    const villaResult = await pool.query('SELECT villa_id FROM villas WHERE villa_id = $1', [villa_id]);
    if (villaResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Villa not found', null, 'VILLA_NOT_FOUND'));
    }

    // Check if already in wishlist
    const existingItem = await pool.query(
      'SELECT wishlist_item_id FROM wishlist_items WHERE user_id = $1 AND villa_id = $2',
      [req.user.user_id, villa_id]
    );

    if (existingItem.rows.length > 0) {
      return res.status(400).json(createErrorResponse('Villa already in wishlist', null, 'VILLA_ALREADY_IN_WISHLIST'));
    }

    // Add to wishlist
    const wishlist_item_id = generateId();
    const result = await pool.query(
      'INSERT INTO wishlist_items (wishlist_item_id, user_id, villa_id, added_at) VALUES ($1, $2, $3, $4) RETURNING *',
      [wishlist_item_id, req.user.user_id, villa_id, new Date().toISOString()]
    );

    const newItem = result.rows[0];

    res.status(201).json(newItem);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Add to wishlist error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  DELETE /api/wishlists/{wishlist_item_id}
  Removes a specific item from the user's wishlist
  Only allows deletion if the item belongs to the authenticated user
*/
app.delete('/api/wishlists/:wishlist_item_id', authenticateToken, async (req, res) => {
  try {
    const { wishlist_item_id } = req.params;

    // Check if item exists and belongs to user
    const itemResult = await pool.query(
      'SELECT user_id FROM wishlist_items WHERE wishlist_item_id = $1',
      [wishlist_item_id]
    );

    if (itemResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Wishlist item not found', null, 'WISHLIST_ITEM_NOT_FOUND'));
    }

    if (itemResult.rows[0].user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Not authorized to delete this item', null, 'AUTHORIZATION_ERROR'));
    }

    // Delete the item
    await pool.query('DELETE FROM wishlist_items WHERE wishlist_item_id = $1', [wishlist_item_id]);

    res.status(204).send();
  } catch (error) {
    console.error('Delete wishlist item error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// INQUIRY ROUTES

/*
  POST /api/inquiries
  Sends a new inquiry about a villa to the host
  Creates a new inquiry record with sender details and message
*/
app.post('/api/inquiries', authenticateToken, async (req, res) => {
  try {
    const validatedData = createInquiryInputSchema.parse(req.body);
    const { user_id, villa_id, message } = validatedData;

    // Verify the user_id matches the authenticated user
    if (user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Cannot send inquiry for another user', null, 'AUTHORIZATION_ERROR'));
    }

    // Check if villa exists
    const villaResult = await pool.query('SELECT villa_id FROM villas WHERE villa_id = $1', [villa_id]);
    if (villaResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Villa not found', null, 'VILLA_NOT_FOUND'));
    }

    // Create inquiry
    const inquiry_id = generateId();
    const result = await pool.query(
      'INSERT INTO inquiries (inquiry_id, user_id, villa_id, message, created_at, is_read) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [inquiry_id, user_id, villa_id, message, new Date().toISOString(), false]
    );

    const newInquiry = result.rows[0];

    res.status(201).json(newInquiry);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Create inquiry error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  PATCH /api/inquiries/{inquiry_id}/read
  Marks a specific inquiry as read
  Only allows villa hosts to mark inquiries about their villas as read
*/
app.patch('/api/inquiries/:inquiry_id/read', authenticateToken, async (req, res) => {
  try {
    const { inquiry_id } = req.params;

    // Get inquiry and villa information
    const inquiryResult = await pool.query(`
      SELECT i.*, v.host_user_id
      FROM inquiries i
      JOIN villas v ON i.villa_id = v.villa_id
      WHERE i.inquiry_id = $1
    `, [inquiry_id]);

    if (inquiryResult.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Inquiry not found', null, 'INQUIRY_NOT_FOUND'));
    }

    const inquiry = inquiryResult.rows[0];

    // Check if user is the villa host
    if (inquiry.host_user_id !== req.user.user_id) {
      return res.status(403).json(createErrorResponse('Not authorized to mark this inquiry as read', null, 'AUTHORIZATION_ERROR'));
    }

    // Mark as read
    await pool.query('UPDATE inquiries SET is_read = $1 WHERE inquiry_id = $2', [true, inquiry_id]);

    res.json({ message: 'Inquiry marked as read' });
  } catch (error) {
    console.error('Mark inquiry read error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// UTILITY ROUTES

/*
  GET /api/health
  Health check endpoint to verify server status
*/
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Static file serving for uploaded images
app.get('/api/storage/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(storageDir, filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json(createErrorResponse('File not found', null, 'FILE_NOT_FOUND'));
  }
});

// File upload endpoint
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json(createErrorResponse('No file uploaded', null, 'NO_FILE_UPLOADED'));
  }

  const fileUrl = `/api/storage/${req.file.filename}`;
  
  res.json({
    message: 'File uploaded successfully',
    file_url: fileUrl,
    filename: req.file.filename
  });
});

// Catch-all route for SPA routing (excluding /api routes)
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

export { app, pool };

// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port} and listening on 0.0.0.0`);
});