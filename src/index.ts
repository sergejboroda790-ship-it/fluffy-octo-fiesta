import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware для проверки токена
const verifyToken = (req: any, res: any, next: any) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = (decoded as any).id;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// РЕГИСТРАЦИЯ
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name }
    });
    
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.json({ token, user });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

// ЛОГИН
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.json({ token, user });
  } catch (err) {
    res.status(400).json({ error: 'Login failed' });
  }
});

// СОЗДАНИЕ ОБЪЯВЛЕНИЯ
app.post('/api/listings', verifyToken, async (req, res) => {
  try {
    const { title, description, category, price, location, images } = req.body;
    
    const listing = await prisma.listing.create({
      data: {
        title,
        description,
        category,
        price,
        location,
        images: images || [],
        userId: req.userId
      }
    });
    
    res.json(listing);
  } catch (err) {
    res.status(400).json({ error: 'Failed to create listing' });
  }
});

// ПОЛУЧИТЬ ВСЕ ОБЪЯВЛЕНИЯ
app.get('/api/listings', async (req, res) => {
  try {
    const listings = await prisma.listing.findMany({
      where: { status: 'active' },
      include: { user: { select: { id: true, name: true, avatar: true } } }
    });
    res.json(listings);
  } catch (err) {
    res.status(400).json({ error: 'Failed to fetch listings' });
  }
});

// ПОЛУЧИТЬ ОБЪЯВЛЕНИЕ ПО ID
app.get('/api/listings/:id', async (req, res) => {
  try {
    const listing = await prisma.listing.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { user: true, messages: true, reviews: true }
    });
    res.json(listing);
  } catch (err) {
    res.status(400).json({ error: 'Failed to fetch listing' });
  }
});

// УДАЛИТЬ ОБЪЯВЛЕНИЕ
app.delete('/api/listings/:id', verifyToken, async (req, res) => {
  try {
    const listing = await prisma.listing.findUnique({
      where: { id: parseInt(req.params.id) }
    });
    
    if (listing?.userId !== req.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await prisma.listing.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: 'Listing deleted' });
  } catch (err) {
    res.status(400).json({ error: 'Failed to delete listing' });
  }
});

// ДОБАВИТЬ В ИЗБРАННОЕ
app.post('/api/favorites/:listingId', verifyToken, async (req, res) => {
  try {
    const favorite = await prisma.favorite.create({
      data: {
        userId: req.userId,
        listingId: parseInt(req.params.listingId)
      }
    });
    res.json(favorite);
  } catch (err) {
    res.status(400).json({ error: 'Failed to add favorite' });
  }
});

// ПОЛУЧИТЬ ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { listings: true, reviews: true }
    });
    res.json(user);
  } catch (err) {
    res.status(400).json({ error: 'Failed to fetch user' });
  }
});

// ОБНОВИТЬ ПРОФИЛЬ
app.put('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const { name, phone, city, avatar } = req.body;
    
    const user = await prisma.user.update({
      where: { id: req.userId },
      data: { name, phone, city, avatar }
    });
    
    res.json(user);
  } catch (err) {
    res.status(400).json({ error: 'Failed to update profile' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
