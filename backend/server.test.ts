import { app, pool } from './server';
import request from 'supertest';
import { JWT_SECRET } from './config'; // Assuming config module exists

// Test user credentials (plain text for testing)
const TEST_USER = {
  email: 'test@example.com',
  password: 'password123',
  full_name: 'Test User'
};

// Test villa data
const TEST_VILLA = {
  villa_id: 'villa-123',
  title: 'Test Villa',
  price_per_night: 200,
  location: 'Test Location'
};

// Test wishlist item
const TEST_WISHLIST_ITEM = {
  villa_id: 'villa-123'
};

// Mock JWT token
const createToken = (userId) => {
  // In real implementation, use jwt.sign
  return `mock-jwt-${userId}`;
};

describe('Backend API Tests', () => {
  beforeAll(async () => {
    // Seed test data
    await pool.query(`
      INSERT INTO users (user_id, full_name, email, password)
      VALUES ('test-user-123', $1, $2, $3)`,
      [TEST_USER.full_name, TEST_USER.email, TEST_USER.password]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM users WHERE user_id = $1', ['test-user-123']);
    await pool.query('DELETE FROM wishlist_items WHERE villa_id = $1', [TEST_VILLA.villa_id]);
  });

  describe('Auth Endpoints', () => {
    test('should register new user', async () => {
      const response = await request(app)
       .post('/auth/register')
       .send({
          full_name: 'New User',
          email: 'new@example.com',
          password: 'password123'
        });
      
      expect(response.statusCode).toBe(201);
      expect(response.body).toHaveProperty('token');
    });

    test('should login existing user', async () => {
      const response = await request(app)
       .post('/auth/login')
       .send({
          email: TEST_USER.email,
          password: TEST_USER.password
        });
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('token');
    });

    test('should fail login with wrong password', async () => {
      const response = await request(app)
       .post('/auth/login')
       .send({
          email: TEST_USER.email,
          password: 'wrongpassword'
        });
      
      expect(response.statusCode).toBe(401);
    });
  });

  describe('User Endpoints', () => {
    let authToken;

    beforeAll(async () => {
      // Get auth token for subsequent tests
      const loginResponse = await request(app)
       .post('/auth/login')
       .send(TEST_USER);
      authToken = loginResponse.body.token;
    });

    test('should get user profile', async () => {
      const response = await request(app)
       .get(`/users/test-user-123`)
       .set("Authorization", `Bearer ${authToken}`);
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toEqual(expect.objectContaining({
        full_name: TEST_USER.full_name,
        email: TEST_USER.email
      }));
    });

    test('should return 404 for non-existent user', async () => {
      const response = await request(app)
       .get('/users/non-existent')
       .set("Authorization", `Bearer ${authToken}`);
      
      expect(response.statusCode).toBe(404);
    });
  });

  describe('Wishlist Endpoints', () => {
    let authToken;

    beforeAll(async () => {
      // Get auth token
      const loginResponse = await request(app)
       .post('/auth/login')
       .send(TEST_USER);
      authToken = loginResponse.body.token;
    });

    test('should add to wishlist', async () => {
      const response = await request(app)
       .post('/wishlists')
       .set("Authorization", `Bearer ${authToken}`)
       .send(TEST_WISHLIST_ITEM);
      
      expect(response.statusCode).toBe(201);
      expect(response.body).toHaveProperty('wishlist_item_id');
    });

    test('should get wishlist items', async () => {
      const response = await request(app)
       .get('/wishlists')
       .set("Authorization", `Bearer ${authToken}`);
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toBeInstanceOf(Array);
    });

    test('should delete wishlist item', async () => {
      // First add an item
      const addItemResponse = await request(app)
       .post('/wishlists')
       .set("Authorization", `Bearer ${authToken}`)
       .send(TEST_WISHLIST_ITEM);
      
      const itemId = addItemResponse.body.wishlist_item_id;
      
      const deleteResponse = await request(app)
       .delete(`/wishlists/${itemId}`)
       .set("Authorization", `Bearer ${authToken}`);
      
      expect(deleteResponse.statusCode).toBe(204);
    });
  });

  describe('Villa Endpoints', () => {
    let authToken;

    beforeAll(async () => {
      // Get auth token for host user
      // Assuming we have a host user test setup
    });

    test('should search villas', async () => {
      const response = await request(app)
       .get('/villas')
       .query({
          location: 'Test Location',
          price_min: 100,
          price_max: 300
        });
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toBeInstanceOf(Array);
    });

    test('should update villa photos', async () => {
      const photos = [
        { photo_id: 'photo-1', url: 'test1.jpg', is_primary: true },
        { photo_id: 'photo-2', url: 'test2.jpg', is_primary: false }
      ];

      const response = await request(app)
       .patch(`/villas/${TEST_VILLA.villa_id}/photos`)
       .set("Authorization", `Bearer ${authToken}`)
       .send(photos);
      
      expect(response.statusCode).toBe(200);
      expect(response.body.photos).toEqual(expect.arrayContaining([
        expect.objectContaining({ is_primary: true })
      ]));
    });
  });

  describe('Inquiry Endpoints', () => {
    let authToken;

    beforeAll(async () => {
      // Get auth token for user
    });

    test('should create inquiry', async () => {
      const inquiry = {
        user_id: 'test-user-123',
        villa_id: TEST_VILLA.villa_id,
        message: 'Test inquiry message'
      };

      const response = await request(app)
       .post('/inquiries')
       .set("Authorization", `Bearer ${authToken}`)
       .send(inquiry);
      
      expect(response.statusCode).toBe(201);
      expect(response.body).toHaveProperty('inquiry_id');
    });

    test('should mark inquiry as read', async () => {
      // First create an inquiry
      const createResponse = await request(app)
       .post('/inquiries')
       .set("Authorization", `Bearer ${authToken}`)
       .send({
          user_id: 'test-user-123',
          villa_id: TEST_VILLA.villa_id,
          message: 'Test message'
        });
      
      const inquiryId = createResponse.body.inquiry_id;
      
      const updateResponse = await request(app)
       .patch(`/inquiries/${inquiryId}/read`)
       .set("Authorization", `Bearer ${authToken}`);
      
      expect(updateResponse.statusCode).toBe(200);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid JWT', async () => {
      const response = await request(app)
       .get('/users/test-user-123')
       .set("Authorization", 'Bearer invalid-token');
      
      expect(response.statusCode).toBe(401);
    });

    test('should handle missing path parameter', async () => {
      const response = await request(app)
       .get('/users/');
      
      expect(response.statusCode).toBe(404);
    });
  });
});