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

// Підключення до бази даних
async function connectToDatabase() {
  try {
    await client.connect();
    console.log("✅ Підключено до MongoDB");
    
    // Створюємо індекс для швидшого пошуку по authCodeHash
    const db = client.db("Blockvote");
    const usersCollection = db.collection("users");
    await usersCollection.createIndex({ "authCodeHash": 1 });
    console.log("✅ Індекс для authCodeHash створено");
  } catch (err) {
    console.log("❌ Помилка підключення до MongoDB", err);
  }
}

// Структура для користувача
const db = client.db("Blockvote");
const usersCollection = db.collection("users");

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

// Покращена генерація складного коду для авторизації
const generateAuthCode = () => {
  // Використовуємо різні набори символів для максимальної ентропії
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  // Генеруємо випадкову довжину коду від 24 до 32 символів
  const codeLength = Math.floor(Math.random() * 9) + 24;
  
  let authCode = '';
  
  // Забезпечуємо наявність принаймні одного символу з кожної категорії
  authCode += uppercase[Math.floor(Math.random() * uppercase.length)];
  authCode += lowercase[Math.floor(Math.random() * lowercase.length)];
  authCode += numbers[Math.floor(Math.random() * numbers.length)];
  authCode += specialChars[Math.floor(Math.random() * specialChars.length)];
  
  // Заповнюємо решту коду випадковими символами
  const allChars = uppercase + lowercase + numbers + specialChars;
  
  for (let i = 4; i < codeLength; i++) {
    // Використовуємо crypto.randomBytes для кращої ентропії
    const randomByte = crypto.randomBytes(1)[0];
    authCode += allChars[randomByte % allChars.length];
  }
  
  // Перемішуємо символи для додаткової безпеки
  return authCode.split('').sort(() => {
    const randomBytes = crypto.randomBytes(1)[0];
    return randomBytes - 128;
  }).join('');
};

// Функція для створення хешу коду (для швидкого пошуку)
const createAuthCodeHash = (authCode) => {
  return crypto.createHash('sha256').update(authCode).digest('hex');
};

// Реєстрація користувача
app.post('/register', async (req, res) => {
  const { username, status, groupId } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Необхідно вказати ім'я користувача!" });
  }

  try {
    // Перевірка, чи існує користувач з таким же іменем
    const existingUser = await usersCollection.findOne({ username });
    
    if (existingUser) {
      return res.status(400).json({ 
        message: "Користувач з таким іменем вже існує!" 
      });
    }
    
    // Генерація складнішого коду для авторизації
    const authCode = generateAuthCode();
    const hashedAuthCode = await bcrypt.hash(authCode, 10);
    const authCodeHash = createAuthCodeHash(authCode);

    // За замовчуванням - звичайний користувач, якщо не вказано інше
    const userStatus = status === "admin" ? "admin" : "user";
    
    // Використовуємо переданий groupId або генеруємо новий
    const userGroupId = groupId || generateGroupId();

    // Створення нового користувача
    const newUser = {
      username,
      authCode: hashedAuthCode,
      authCodeHash, // Додаємо хеш для швидкого пошуку
      status: userStatus,
      groupId: userGroupId,
      createdAt: new Date()
    };

    await usersCollection.insertOne(newUser);
    res.status(201).json({ 
      message: "Користувач зареєстрований!",
      authCode, // Повертаємо нехешований код для входу
      status: userStatus,
      groupId: userGroupId
    });
  } catch (error) {
    console.error("❌ Помилка при реєстрації:", error);
    res.status(500).json({ message: "Помилка сервера при реєстрації користувача" });
  }
});

// Масова реєстрація користувачів (оновлений ендпоінт)
app.post('/register-bulk', async (req, res) => {
  const { userCount } = req.body;
  
  // Перевірка валідності параметрів
  if (!userCount || isNaN(userCount) || userCount < 1 || userCount > 100) {
    return res.status(400).json({ 
      message: "Некоректна кількість користувачів! Введіть число від 1 до 100." 
    });
  }
  
  try {
    // Створюємо новий groupId для групи
    const groupId = generateGroupId();
    
    // Масив для зберігання створених користувачів
    const users = [];
    
    // Спочатку створюємо адміністратора
    const adminAuthCode = generateAuthCode();
    const adminHashedAuthCode = await bcrypt.hash(adminAuthCode, 10);
    const adminAuthCodeHash = createAuthCodeHash(adminAuthCode);
    
    const adminUser = {
      username: `admin_${groupId.substring(0, 4)}`,
      authCode: adminHashedAuthCode,
      authCodeHash: adminAuthCodeHash,
      status: "admin",
      groupId,
      createdAt: new Date()
    };
    
    // Додаємо адміністратора до масиву
    users.push(adminUser);
    
    // Створюємо звичайних користувачів
    for (let i = 0; i < userCount; i++) {
      const authCode = generateAuthCode();
      const hashedAuthCode = await bcrypt.hash(authCode, 10);
      const authCodeHash = createAuthCodeHash(authCode);
      
      const user = {
        username: `user_${groupId.substring(0, 4)}_${i + 1}`,
        authCode: hashedAuthCode,
        authCodeHash,
        status: "user",
        groupId,
        createdAt: new Date()
      };
      
      // Зберігаємо незахешований код для повернення клієнту
      user.originalAuthCode = authCode;
      users.push(user);
    }
    
    // Підготовлюємо користувачів для вставки в БД (без originalAuthCode)
    const usersForDb = users.map(user => {
      const { originalAuthCode, ...userForDb } = user;
      return userForDb;
    });
    
    // Вставляємо всіх користувачів в БД
    await usersCollection.insertMany(usersForDb);
    
    // Підготовлюємо відповідь для клієнта
    const usersToReturn = users.slice(1).map(user => ({
      username: user.username,
      authCode: user.originalAuthCode,
      status: user.status,
      groupId: user.groupId
    }));
    
    // Повертаємо відповідь з кодами авторизації
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

// ОПТИМІЗОВАНА авторизація користувача за кодом
app.post('/login', async (req, res) => {
  const { authCode } = req.body;

  if (!authCode) {
    return res.status(400).json({ message: "Не передано код авторизації!" });
  }

  try {
    // Створюємо хеш з переданого коду для швидкого пошуку
    const authCodeHash = createAuthCodeHash(authCode);
    
    // Швидкий пошук по індексу замість перебору всіх користувачів
    const foundUser = await usersCollection.findOne({ authCodeHash });
    
    if (!foundUser) {
      // Швидка відповідь при невірному коді - без bcrypt порівняння
      return res.status(401).json({ message: "Невірний код авторизації!" });
    }

    // Перевіряємо bcrypt хеш тільки для знайденого користувача
    const isMatch = await bcrypt.compare(authCode, foundUser.authCode);
    
    if (!isMatch) {
      return res.status(401).json({ message: "Невірний код авторизації!" });
    }

    // Генеруємо токен після успішної авторизації
    const token = jwt.sign({ 
      userId: foundUser._id,
      status: foundUser.status || "user",
      groupId: foundUser.groupId || generateGroupId() 
    }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    // Зберігаємо токен у БД
    await usersCollection.updateOne(
      { _id: foundUser._id },
      { $set: { sessionToken: token, lastLogin: new Date() } }
    );

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

// Перевірка авторизації
app.get('/check-auth', authenticateToken, (req, res) => {
  res.status(200).json({ 
    message: 'Авторизація пройдена', 
    userId: req.user.userId,
    status: req.user.status || "user",
    groupId: req.user.groupId
  });
});

// Отримання інформації про користувача
app.get('/user', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });

    if (!user) {
      return res.status(404).json({ message: 'Користувач не знайдений' });
    }

    // Відповідь з даними користувача (без конфіденційної інформації)
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
