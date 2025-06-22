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
const usersCollection = db.collection("users");

// Cache для кодів авторизації (Redis-альтернатива)
const authCodeCache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 години

// Функція завантаження кешу з БД при старті сервера
async function loadCacheFromDB() {
  try {
    console.log("🔄 Завантаження кешу з бази даних...");
    
    // Отримуємо всіх користувачів за останні 24 години
    const yesterday = new Date(Date.now() - CACHE_TTL);
    const recentUsers = await usersCollection.find({
      createdAt: { $gte: yesterday },
      authCodeId: { $exists: true }
    }, {
      projection: { authCodeId: 1, authCodeHash: 1, createdAt: 1 }
    }).toArray();
    
    console.log(`📦 Знайдено ${recentUsers.length} користувачів для кешування`);
    
    // Завантажуємо в кеш (без plaintextового коду, він недоступний)
    for (const user of recentUsers) {
      authCodeCache.set(user.authCodeId, {
        authCodeHash: user.authCodeHash,
        timestamp: user.createdAt.getTime(),
        fromDB: true // Позначаємо що завантажено з БД
      });
    }
    
    console.log(`✅ Кеш завантажено: ${authCodeCache.size} записів`);
  } catch (error) {
    console.error("❌ Помилка завантаження кешу:", error);
  }
}

// Функція очищення кешу від застарілих записів
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of authCodeCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      authCodeCache.delete(key);
    }
  }
}, 60 * 60 * 1000); // Очищуємо кожну годину

// Створення індексів для оптимізації
async function createIndexes() {
  try {
    console.log("📝 Початок створення індексів...");
    
    // Перевіряємо існуючі індекси
    const existingIndexes = await usersCollection.indexes();
    console.log("📋 Знайдено існуючих індексів:", existingIndexes.length);
    
    // Видаляємо проблемний індекс якщо він існує
    try {
      await usersCollection.dropIndex("authCodeHash_1");
      console.log("🗑️ Видалено старий індекс authCodeHash_1");
    } catch (dropError) {
      console.log("ℹ️ Старий індекс не знайдено (це нормально)");
    }
    
    // Очищуємо документи з null або відсутнім authCodeHash
    console.log("🧹 Очищення проблемних документів...");
    const deleteResult = await usersCollection.deleteMany({ 
      $or: [
        { authCodeHash: null }, 
        { authCodeHash: { $exists: false } },
        { authCodeHash: "" }
      ]
    });
    
    if (deleteResult.deletedCount > 0) {
      console.log(`🗑️ Видалено ${deleteResult.deletedCount} документів з некоректним authCodeHash`);
    }
    
    console.log("🔨 Створення індексів...");
    
    // Створюємо унікальний індекс для authCodeId (замість хешу)
    await usersCollection.createIndex(
      { authCodeId: 1 }, 
      { 
        unique: true,
        name: "authCodeId_unique"
      }
    );
    console.log("✅ Створено унікальний індекс для authCodeId");
    
    // Створюємо унікальний індекс для username
    await usersCollection.createIndex(
      { username: 1 }, 
      { 
        unique: true,
        name: "username_unique"
      }
    );
    console.log("✅ Створено унікальний індекс для username");
    
    // Створюємо індекс для groupId
    await usersCollection.createIndex(
      { groupId: 1 },
      { name: "groupId_index" }
    );
    console.log("✅ Створено індекс для groupId");
    
    // Створюємо розріджений індекс для sessionToken
    await usersCollection.createIndex(
      { sessionToken: 1 }, 
      { 
        sparse: true,
        name: "sessionToken_sparse"
      }
    );
    console.log("✅ Створено розріджений індекс для sessionToken");
    
    console.log("🎉 Всі індекси створено успішно!");
    
  } catch (error) {
    console.error("❌ Помилка при створенні індексів:", error.message);
    throw error;
  }
}

// Підключення до бази даних
async function connectToDatabase() {
  try {
    await client.connect();
    console.log("✅ Підключено до MongoDB");
    await createIndexes();
    await loadCacheFromDB(); // Завантажуємо кеш після підключення
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

// Оптимізована генерація коду авторизації (коротший але все ще безпечний)
const generateAuthCode = () => {
  // Зменшуємо довжину до 16-20 символів для швидкості
  const codeLength = Math.floor(Math.random() * 5) + 16;
  
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  
  let code = '';
  for (let i = 0; i < codeLength; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  
  return code;
};

// Генерація унікального ID для коду авторизації
const generateAuthCodeId = () => crypto.randomBytes(12).toString('hex');

// Функція для створення хешу коду авторизації (знижений cost factor)
const createAuthCodeHash = async (authCode) => {
  // Зменшуємо cost factor з 12 до 10 для швидкості
  return await bcrypt.hash(authCode, 10);
};

// Реєстрація користувача (оптимізована)
app.post('/register', async (req, res) => {
  const { username, status, groupId } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Необхідно вказати ім'я користувача!" });
  }

  try {
    const authCode = generateAuthCode();
    const authCodeId = generateAuthCodeId();
    const authCodeHash = await createAuthCodeHash(authCode);

    const userStatus = status === "admin" ? "admin" : "user";
    const userGroupId = groupId || generateGroupId();

    // Зберігаємо в кеш для швидкого пошуку
    authCodeCache.set(authCodeId, {
      authCode,
      authCodeHash,
      timestamp: Date.now()
    });

    // Створення нового користувача з authCodeId як ключем
    const newUser = {
      username,
      authCodeId, // Використовуємо ID замість хешу
      authCodeHash, // Зберігаємо хеш для безпеки
      status: userStatus,
      groupId: userGroupId,
      createdAt: new Date()
    };

    await usersCollection.insertOne(newUser);
    res.status(201).json({ 
      message: "Користувач зареєстрований!",
      authCode,
      status: userStatus,
      groupId: userGroupId
    });
  } catch (error) {
    if (error.code === 11000) {
      if (error.keyPattern?.username) {
        return res.status(400).json({ message: "Користувач з таким іменем вже існує!" });
      }
      return res.status(500).json({ message: "Помилка генерації коду, спробуйте ще раз" });
    }
    console.error("❌ Помилка при реєстрації:", error);
    res.status(500).json({ message: "Помилка сервера при реєстрації користувача" });
  }
});

// Масова реєстрація користувачів (оптимізована)
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
    
    // Створюємо адміністратора
    const adminAuthCode = generateAuthCode();
    const adminAuthCodeId = generateAuthCodeId();
    const adminAuthCodeHash = await createAuthCodeHash(adminAuthCode);
    
    // Додаємо в кеш
    authCodeCache.set(adminAuthCodeId, {
      authCode: adminAuthCode,
      authCodeHash: adminAuthCodeHash,
      timestamp: Date.now()
    });
    
    const adminUser = {
      username: `admin_${groupId.substring(0, 4)}`,
      authCodeId: adminAuthCodeId,
      authCodeHash: adminAuthCodeHash,
      status: "admin",
      groupId,
      createdAt: new Date()
    };
    
    users.push(adminUser);
    
    // Створюємо звичайних користувачів паралельно
    const userPromises = [];
    for (let i = 0; i < userCount; i++) {
      const promise = (async () => {
        const authCode = generateAuthCode();
        const authCodeId = generateAuthCodeId();
        const authCodeHash = await createAuthCodeHash(authCode);
        
        // Додаємо в кеш
        authCodeCache.set(authCodeId, {
          authCode,
          authCodeHash,
          timestamp: Date.now()
        });
        
        const user = {
          username: `user_${groupId.substring(0, 4)}_${i + 1}`,
          authCodeId,
          authCodeHash,
          status: "user",
          groupId,
          createdAt: new Date()
        };
        
        usersToReturn.push({
          username: user.username,
          authCode: authCode,
          status: user.status,
          groupId: user.groupId
        });
        
        return user;
      })();
      
      userPromises.push(promise);
    }
    
    const regularUsers = await Promise.all(userPromises);
    users.push(...regularUsers);
    
    await usersCollection.insertMany(users);
    
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

// МАКСИМАЛЬНО оптимізована авторизація
app.post('/login', async (req, res) => {
  const { authCode } = req.body;

  if (!authCode) {
    return res.status(400).json({ message: "Не передано код авторизації!" });
  }

  try {
    let foundUser = null;
    let matchedAuthCodeId = null;

    // 1. Спочатку шукаємо прямий збіг в кеші (для свіжих користувачів)
    for (const [authCodeId, cacheData] of authCodeCache.entries()) {
      if (cacheData.authCode === authCode) {
        matchedAuthCodeId = authCodeId;
        break;
      }
    }

    if (matchedAuthCodeId) {
      // Знайшли в кеші - шукаємо користувача за authCodeId
      foundUser = await usersCollection.findOne({ authCodeId: matchedAuthCodeId });
    }

    // 2. Якщо не знайшли прямий збіг, перевіряємо хеші в кеші
    if (!foundUser) {
      for (const [authCodeId, cacheData] of authCodeCache.entries()) {
        if (cacheData.fromDB && cacheData.authCodeHash) {
          const isMatch = await bcrypt.compare(authCode, cacheData.authCodeHash);
          if (isMatch) {
            foundUser = await usersCollection.findOne({ authCodeId });
            break;
          }
        }
      }
    }

    // 3. Останній шанс - повний пошук в БД (рідкісний випадок)
    if (!foundUser) {
      console.log("⚠️ Повний пошук в БД (повільний)");
      
      // Оптимізований запит з лімітом та сортуванням
      const users = await usersCollection.find({
        authCodeHash: { $exists: true, $ne: null }
      }, {
        projection: { authCodeHash: 1, username: 1, status: 1, groupId: 1, authCodeId: 1 },
        sort: { createdAt: -1 }, // Спочатку нові користувачі
        limit: 1000 // Обмежуємо пошук
      }).toArray();
      
      // Пакетна перевірка з обмеженою кількістю одночасних операцій
      const batchSize = 5; // Зменшуємо для економії ресурсів
      for (let i = 0; i < users.length; i += batchSize) {
        const batch = users.slice(i, i + batchSize);
        const promises = batch.map(async (user) => {
          if (user.authCodeHash) {
            const isMatch = await bcrypt.compare(authCode, user.authCodeHash);
            if (isMatch) {
              // Додаємо знайденого користувача в кеш
              if (user.authCodeId) {
                authCodeCache.set(user.authCodeId, {
                  authCodeHash: user.authCodeHash,
                  timestamp: Date.now(),
                  fromDB: true
                });
              }
              return user;
            }
          }
          return null;
        });
        
        const results = await Promise.all(promises);
        foundUser = results.find(result => result !== null);
        
        if (foundUser) break;
      }
    }

    if (!foundUser) {
      return res.status(401).json({ message: "Невірний код авторизації!" });
    }

    // Генеруємо токен
    const token = jwt.sign({ 
      userId: foundUser._id,
      status: foundUser.status || "user",
      groupId: foundUser.groupId || generateGroupId() 
    }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    // Асинхронно оновлюємо токен у БД (не чекаємо завершення)
    usersCollection.updateOne(
      { _id: foundUser._id },
      { $set: { sessionToken: token, lastLogin: new Date() } }
    ).catch(err => console.error("Помилка оновлення токена:", err));

    return res.status(200).json({
      message: "Авторизація успішна!",
      token,
      status: foundUser.status || "user",
      groupId: foundUser.groupId
    });
  } catch (error) {
    console.error("❌ Помилка під час авторизації:", error);
    return res.status(500).json({ message: "Внутрішня помилка сервера" });
  }
});

// Перевірка авторизації (залишаємо для сумісності)
app.get('/check-auth', authenticateToken, (req, res) => {
  res.status(200).json({ 
    message: 'Авторизація пройдена', 
    userId: req.user.userId,
    status: req.user.status || "user",
    groupId: req.user.groupId
  });
});

// Додатковий endpoint для перевірки стану авторизації (швидкий)
app.get('/auth-status', authenticateToken, (req, res) => {
  // Швидкий endpoint без запитів до БД
  res.status(200).json({ 
    authenticated: true,
    userId: req.user.userId,
    status: req.user.status || "user",
    groupId: req.user.groupId
  });
});

// Endpoint для отримання статистики кешу (для відладки)
app.get('/cache-stats', (req, res) => {
  const cacheSize = authCodeCache.size;
  const fromDB = Array.from(authCodeCache.values()).filter(v => v.fromDB).length;
  const fresh = cacheSize - fromDB;
  
  res.json({
    totalCached: cacheSize,
    fromDatabase: fromDB,
    freshRegistrations: fresh,
    message: `Кеш: ${cacheSize} записів (${fresh} нових, ${fromDB} з БД)`
  });
});

// Отримання інформації про користувача
app.get('/user', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne(
      { _id: new ObjectId(req.user.userId) },
      { projection: { username: 1, status: 1, groupId: 1 } }
    );

    if (!user) {
      return res.status(404).json({ message: 'Користувач не знайдений' });
    }

    res.status(200).json({
      username: user.username,
      status: user.status || "user",
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
    status: req.user.status || "user",
    groupId: req.user.groupId
  });
});

// Тестовий маршрут
app.get('/test', (req, res) => {
  res.send("Сервер працює!");
});

// Запуск сервера
connectToDatabase().then(() => {
  app.listen(port, () => {
    console.log(`✅ Сервер аутентифікації запущено на порту ${port}`);
  });
});
