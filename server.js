const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv'); 

// Завантаження змінних оточення
dotenv.config();

// Створюємо додаток
const app = express();
const port = process.env.AUTH_PORT;

// URI для підключення до MongoDB - використовуємо змінну середовища
const uri = process.env.MONGODB_URI;

// Секретний ключ для JWT - використовуємо змінну середовища
const JWT_SECRET = process.env.JWT_SECRET;

// Час життя токена
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;

// Підключення до MongoDB Atlas через MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Middleware для парсингу JSON
app.use(bodyParser.json());

// Додаємо middleware для CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Структура для користувача
const db = client.db("Blockvote");
const usersCollection = db.collection("users_v2"); // Нова колекція для нової структури

// In-memory кеш для швидкого пошуку останніх авторизацій
const authCache = new Map();
const CACHE_SIZE = 1000;

// Створення індексів для максимальної швидкості
async function createIndexes() {
  try {
    // Основний унікальний індекс - authCodeHash як первинний ключ
    await usersCollection.createIndex({ authCodeHash: 1 }, { unique: true });
    
    // Додатковий індекс для username
    await usersCollection.createIndex({ username: 1 }, { unique: true });
    
    // Індекс для groupId
    await usersCollection.createIndex({ groupId: 1 });
    
    console.log("✅ Індекси створено успішно");
  } catch (error) {
    console.log("⚠️ Помилка створення індексів:", error.message);
  }
}

// Підключення до бази даних
async function connectToDatabase() {
  try {
    await client.connect();
    console.log("✅ Підключено до MongoDB");
    await createIndexes();
  } catch (err) {
    console.log("❌ Помилка підключення до MongoDB", err);
  }
}

// Middleware для перевірки авторизації
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Необхідна авторизація' });
  
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Необхідна авторизація' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Невірний токен авторизації' });
    
    req.user = decoded;
    next();
  });
};

// Генерація випадкового groupId
const generateGroupId = () => crypto.randomBytes(4).toString('hex');

// Генерація ДУЖЕ складного коду авторизації
const generateAuthCode = () => {
  // Довжина від 32 до 48 символів
  const length = Math.floor(Math.random() * 17) + 32;
  
  // Використовуємо всі доступні символи ASCII для максимальної складності
  const upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowerCase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+-=[]{}|;:,.<>?~`';
  
  const allChars = upperCase + lowerCase + numbers + special;
  
  let code = '';
  
  // Забезпечуємо принаймні по одному символу кожного типу
  code += upperCase[Math.floor(Math.random() * upperCase.length)];
  code += lowerCase[Math.floor(Math.random() * lowerCase.length)];
  code += numbers[Math.floor(Math.random() * numbers.length)];
  code += special[Math.floor(Math.random() * special.length)];
  
  // Заповнюємо решту випадковими символами
  for (let i = 4; i < length; i++) {
    code += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Перемішуємо символи
  return code.split('').sort(() => Math.random() - 0.5).join('');
};

// Швидке хешування
const createAuthCodeHash = async (authCode) => {
  return await bcrypt.hash(authCode, 10);
};

// Функція для очищення кешу
const cleanCache = () => {
  if (authCache.size > CACHE_SIZE) {
    const entries = Array.from(authCache.entries());
    const toDelete = entries.slice(0, Math.floor(CACHE_SIZE / 2));
    toDelete.forEach(([key]) => authCache.delete(key));
  }
};

// Реєстрація користувача (нова оптимізована структура)
app.post('/register', async (req, res) => {
  const { username, status, groupId } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Необхідно вказати ім'я користувача!" });
  }

  try {
    // Генерація складного коду
    const authCode = generateAuthCode();
    const authCodeHash = await createAuthCodeHash(authCode);

    const userStatus = status === "admin" ? "admin" : "user";
    const userGroupId = groupId || generateGroupId();

    // НОВА СТРУКТУРА: authCodeHash як _id для максимальної швидкості
    const newUser = {
      _id: authCodeHash, // Хеш коду як первинний ключ
      username,
      status: userStatus,
      groupId: userGroupId,
      createdAt: new Date(),
      lastLogin: null,
      sessionToken: null
    };

    await usersCollection.insertOne(newUser);
    
    // Додаємо в кеш для швидкого доступу
    authCache.set(authCodeHash, newUser);
    cleanCache();
    
    res.status(201).json({ 
      message: "Користувач зареєстрований!",
      authCode,
      status: userStatus,
      groupId: userGroupId
    });
  } catch (error) {
    if (error.code === 11000) {
      if (error.keyValue?.username) {
        return res.status(400).json({ message: "Користувач з таким іменем вже існує!" });
      }
      return res.status(500).json({ message: "Помилка генерації коду, спробуйте ще раз" });
    }
    console.error("❌ Помилка при реєстрації:", error);
    res.status(500).json({ message: "Помилка сервера при реєстрації користувача" });
  }
});

// Масова реєстрація (оптимізована під нову структуру)
app.post('/register-bulk', async (req, res) => {
  const { userCount } = req.body;
  
  if (!userCount || isNaN(userCount) || userCount < 1 || userCount > 100) {
    return res.status(400).json({ 
      message: "Некоректна кількість користувачів! Введіть число від 1 до 100." 
    });
  }
  
  try {
    const groupId = generateGroupId();
    const users = [];
    const usersToReturn = [];
    
    // Адміністратор
    const adminAuthCode = generateAuthCode();
    const adminAuthCodeHash = await createAuthCodeHash(adminAuthCode);
    
    const adminUser = {
      _id: adminAuthCodeHash,
      username: `admin_${groupId.substring(0, 4)}`,
      status: "admin",
      groupId,
      createdAt: new Date(),
      lastLogin: null,
      sessionToken: null
    };
    
    users.push(adminUser);
    authCache.set(adminAuthCodeHash, adminUser);
    
    // Паралельне створення користувачів
    const userPromises = Array.from({ length: userCount }, (_, i) => 
      (async () => {
        const authCode = generateAuthCode();
        const authCodeHash = await createAuthCodeHash(authCode);
        
        const user = {
          _id: authCodeHash,
          username: `user_${groupId.substring(0, 4)}_${i + 1}`,
          status: "user",
          groupId,
          createdAt: new Date(),
          lastLogin: null,
          sessionToken: null
        };
        
        authCache.set(authCodeHash, user);
        
        usersToReturn.push({
          username: user.username,
          authCode: authCode,
          status: user.status,
          groupId: user.groupId
        });
        
        return user;
      })()
    );
    
    const regularUsers = await Promise.all(userPromises);
    users.push(...regularUsers);
    
    // Одна вставка для всіх
    await usersCollection.insertMany(users, { ordered: false });
    
    cleanCache();
    
    res.status(201).json({
      message: "Групу користувачів успішно створено!",
      groupId,
      adminCode: adminAuthCode,
      users: usersToReturn
    });
    
  } catch (error) {
    console.error("❌ Помилка при масовій реєстрації:", error);
    res.status(500).json({ message: "Помилка сервера при створенні користувачів" });
  }
});

// МАКСИМАЛЬНО ШВИДКА авторизація
app.post('/login', async (req, res) => {
  const { authCode } = req.body;

  if (!authCode) {
    return res.status(400).json({ message: "Не передано код авторизації!" });
  }

  try {
    // Створюємо хеш з введеного коду
    const authCodeHash = await bcrypt.hash(authCode, 10);
    
    let foundUser = null;
    
    // 1. Спочатку перевіряємо кеш (найшвидше)
    if (authCache.has(authCodeHash)) {
      foundUser = authCache.get(authCodeHash);
    }
    
    // 2. Якщо не в кеші, то ПРЯМИЙ пошук по _id (найшвидший запит в MongoDB)
    if (!foundUser) {
      foundUser = await usersCollection.findOne({ _id: authCodeHash });
      
      if (foundUser) {
        // Додаємо в кеш для наступних разів
        authCache.set(authCodeHash, foundUser);
        cleanCache();
      }
    }
    
    // 3. Якщо і це не спрацювало, тоді перевіряємо bcrypt (для випадків коли хеші відрізняються)
    if (!foundUser) {
      // Отримуємо невелику кількість останніх користувачів
      const recentUsers = await usersCollection
        .find({})
        .sort({ createdAt: -1 })
        .limit(100)
        .toArray();
      
      for (const user of recentUsers) {
        const isMatch = await bcrypt.compare(authCode, user._id);
        if (isMatch) {
          foundUser = user;
          // Оновлюємо кеш
          authCache.set(user._id, user);
          cleanCache();
          break;
        }
      }
    }

    if (!foundUser) {
      return res.status(401).json({ message: "Невірний код авторизації!" });
    }

    // Генеруємо токен
    const token = jwt.sign({ 
      userId: foundUser._id,
      status: foundUser.status,
      groupId: foundUser.groupId
    }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    // Оновлюємо в базі та кеші
    const updateData = { sessionToken: token, lastLogin: new Date() };
    await usersCollection.updateOne({ _id: foundUser._id }, { $set: updateData });
    
    // Оновлюємо кеш
    foundUser.sessionToken = token;
    foundUser.lastLogin = new Date();
    authCache.set(foundUser._id, foundUser);

    return res.status(200).json({
      message: "Авторизація успішна!",
      token,
      status: foundUser.status,
      groupId: foundUser.groupId
    });
  } catch (error) {
    console.error("❌ Помилка під час авторизації:", error);
    return res.status(500).json({ message: "Внутрішня помилка сервера" });
  }
});

// Перевірка авторизації
app.get('/check-auth', authenticateToken, (req, res) => {
  res.status(200).json({ 
    message: 'Авторизація пройдена', 
    userId: req.user.userId,
    status: req.user.status,
    groupId: req.user.groupId
  });
});

// Отримання інформації про користувача
app.get('/user', authenticateToken, async (req, res) => {
  try {
    let user = null;
    
    // Спочатку перевіряємо кеш
    if (authCache.has(req.user.userId)) {
      user = authCache.get(req.user.userId);
    } else {
      user = await usersCollection.findOne({ _id: req.user.userId });
      if (user) {
        authCache.set(req.user.userId, user);
        cleanCache();
      }
    }

    if (!user) {
      return res.status(404).json({ message: 'Користувач не знайдений' });
    }

    res.status(200).json({
      username: user.username,
      status: user.status,
      groupId: user.groupId,
      userId: req.user.userId
    });
  } catch (error) {
    console.error('❌ Помилка отримання даних користувача:', error);
    res.status(500).json({ message: 'Помилка сервера при отриманні даних користувача' });
  }
});

// Отримання ID користувача
app.get('/user-id', authenticateToken, (req, res) => {
  res.json({ 
    userId: req.user.userId,
    status: req.user.status,
    groupId: req.user.groupId
  });
});

// Тестовий маршрут
app.get('/test', (req, res) => {
  res.send("Швидкий сервер працює!");
});

// Очищення кешу при завершенні
process.on('SIGINT', () => {
  authCache.clear();
  client.close();
  process.exit(0);
});

// Запуск сервера
connectToDatabase().then(() => {
  app.listen(port, () => {
    console.log(`✅ Максимально швидкий сервер запущено на порту ${port}`);
  });
});
