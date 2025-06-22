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
      // Індекс не існує - це нормально
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
    } else {
      console.log("✨ Проблемних документів не знайдено");
    }
    
    // Перевіряємо та видаляємо дублікати authCodeHash
    console.log("🔍 Пошук дублікатів authCodeHash...");
    const duplicates = await usersCollection.aggregate([
      { 
        $match: { 
          authCodeHash: { $exists: true, $ne: null, $ne: "" } 
        } 
      },
      { 
        $group: { 
          _id: "$authCodeHash", 
          count: { $sum: 1 }, 
          docs: { $push: "$_id" } 
        } 
      },
      { 
        $match: { count: { $gt: 1 } } 
      }
    ]).toArray();
    
    if (duplicates.length > 0) {
      console.log(`⚠️ Знайдено ${duplicates.length} груп дублікатів`);
      
      for (const duplicate of duplicates) {
        // Видаляємо всі дублікати крім першого
        const docsToDelete = duplicate.docs.slice(1);
        const deleteResult = await usersCollection.deleteMany({ 
          _id: { $in: docsToDelete } 
        });
        console.log(`🗑️ Видалено ${deleteResult.deletedCount} дублікатів для authCodeHash`);
      }
    } else {
      console.log("✨ Дублікатів не знайдено");
    }
    
    // Перевіряємо та видаляємо дублікати username
    console.log("🔍 Пошук дублікатів username...");
    const usernameDuplicates = await usersCollection.aggregate([
      { 
        $match: { 
          username: { $exists: true, $ne: null, $ne: "" } 
        } 
      },
      { 
        $group: { 
          _id: "$username", 
          count: { $sum: 1 }, 
          docs: { $push: "$_id" } 
        } 
      },
      { 
        $match: { count: { $gt: 1 } } 
      }
    ]).toArray();
    
    if (usernameDuplicates.length > 0) {
      console.log(`⚠️ Знайдено ${usernameDuplicates.length} груп дублікатів username`);
      
      for (const duplicate of usernameDuplicates) {
        // Видаляємо всі дублікати крім першого
        const docsToDelete = duplicate.docs.slice(1);
        const deleteResult = await usersCollection.deleteMany({ 
          _id: { $in: docsToDelete } 
        });
        console.log(`🗑️ Видалено ${deleteResult.deletedCount} дублікатів для username: ${duplicate._id}`);
      }
    } else {
      console.log("✨ Дублікатів username не знайдено");
    }
    
    console.log("🔨 Створення індексів...");
    
    // Створюємо унікальний індекс для authCodeHash
    await usersCollection.createIndex(
      { authCodeHash: 1 }, 
      { 
        unique: true,
        name: "authCodeHash_unique"
      }
    );
    console.log("✅ Створено унікальний індекс для authCodeHash");
    
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
    
    // Створюємо індекс для createdAt (для сортування)
    await usersCollection.createIndex(
      { createdAt: 1 },
      { name: "createdAt_index" }
    );
    console.log("✅ Створено індекс для createdAt");
    
    // Створюємо індекс для lastLogin
    await usersCollection.createIndex(
      { lastLogin: 1 },
      { 
        sparse: true,
        name: "lastLogin_sparse"
      }
    );
    console.log("✅ Створено розріджений індекс для lastLogin");
    
    console.log("🎉 Всі індекси створено успішно!");
    
    // Виводимо статистику
    const totalUsers = await usersCollection.countDocuments();
    const finalIndexes = await usersCollection.indexes();
    console.log(`📊 Загальна кількість користувачів: ${totalUsers}`);
    console.log(`📊 Загальна кількість індексів: ${finalIndexes.length}`);
    
  } catch (error) {
    console.error("❌ Помилка при створенні індексів:", error.message);
    
    // Додаткова діагностика
    if (error.code === 11000) {
      console.error("🔍 Виявлено помилку дублювання ключа. Деталі:", error.keyValue);
      
      // Показуємо проблемні документи
      if (error.keyValue) {
        const problemDocs = await usersCollection.find(error.keyValue).toArray();
        console.error("📄 Проблемні документи:", problemDocs.map(doc => ({
          _id: doc._id,
          username: doc.username,
          authCodeHash: doc.authCodeHash ? "існує" : "відсутній"
        })));
      }
    }
    
    throw error; // Перекидаємо помилку далі
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

// Покращена генерація коду авторизації з більшою складністю
const generateAuthCode = () => {
  // Генеруємо випадкове число від 20 до 32 для довжини коду
  const codeLength = Math.floor(Math.random() * 13) + 20;
  
  // Використовуємо комбінацію різних символів для більшої ентропії
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const numbers = '0123456789';
  const special = '!@#$%^&*';
  
  let code = '';
  
  // Забезпечуємо присутність різних типів символів
  code += chars[Math.floor(Math.random() * chars.length)]; // Літера
  code += numbers[Math.floor(Math.random() * numbers.length)]; // Цифра
  code += special[Math.floor(Math.random() * special.length)]; // Спецсимвол
  
  // Заповнюємо решту випадковими символами
  const allChars = chars + numbers + special;
  for (let i = 3; i < codeLength; i++) {
    code += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Перемішуємо символи для додаткової безпеки
  return code.split('').sort(() => Math.random() - 0.5).join('');
};

// Функція для створення хешу коду авторизації
const createAuthCodeHash = async (authCode) => {
  // Використовуємо більш високий cost factor для безпеки
  return await bcrypt.hash(authCode, 12);
};

// Реєстрація користувача
app.post('/register', async (req, res) => {
  const { username, status, groupId } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Необхідно вказати ім'я користувача!" });
  }

  try {
    // Генерація коду авторизації
    const authCode = generateAuthCode();
    const authCodeHash = await createAuthCodeHash(authCode);

    // За замовчуванням - звичайний користувач, якщо не вказано інше
    const userStatus = status === "admin" ? "admin" : "user";
    
    // Використовуємо переданий groupId або генеруємо новий
    const userGroupId = groupId || generateGroupId();

    // Створення нового користувача з authCodeHash як первинним ключем
    const newUser = {
      username,
      authCodeHash, // Використовуємо як первинний ключ
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
    if (error.code === 11000) {
      // Помилка дублювання ключа
      if (error.keyPattern?.username) {
        return res.status(400).json({ message: "Користувач з таким іменем вже існує!" });
      }
      // Якщо дублюється authCodeHash, генеруємо новий код
      return res.status(500).json({ message: "Помилка генерації коду, спробуйте ще раз" });
    }
    console.error("❌ Помилка при реєстрації:", error);
    res.status(500).json({ message: "Помилка сервера при реєстрації користувача" });
  }
});

// Масова реєстрація користувачів (оптимізована версія)
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
    const usersToReturn = [];
    
    // Спочатку створюємо адміністратора
    const adminAuthCode = generateAuthCode();
    const adminAuthCodeHash = await createAuthCodeHash(adminAuthCode);
    
    const adminUser = {
      username: `admin_${groupId.substring(0, 4)}`,
      authCodeHash: adminAuthCodeHash,
      status: "admin",
      groupId,
      createdAt: new Date()
    };
    
    users.push(adminUser);
    
    // Створюємо звичайних користувачів паралельно для швидкості
    const userPromises = [];
    for (let i = 0; i < userCount; i++) {
      const promise = (async () => {
        const authCode = generateAuthCode();
        const authCodeHash = await createAuthCodeHash(authCode);
        
        const user = {
          username: `user_${groupId.substring(0, 4)}_${i + 1}`,
          authCodeHash,
          status: "user",
          groupId,
          createdAt: new Date()
        };
        
        // Додаємо до масиву для повернення
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
    
    // Чекаємо завершення всіх промісів
    const regularUsers = await Promise.all(userPromises);
    users.push(...regularUsers);
    
    // Вставляємо всіх користувачів в БД одним запитом
    await usersCollection.insertMany(users);
    
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

// Оптимізована авторизація користувача за кодом
app.post('/login', async (req, res) => {
  const { authCode } = req.body;

  if (!authCode) {
    return res.status(400).json({ message: "Не передано код авторизації!" });
  }

  try {
    // Спочатку створюємо хеш з введеного коду
    const authCodeHash = await bcrypt.hash(authCode, 12);
    
    // Шукаємо користувача за хешем (використовуючи індекс)
    let foundUser = await usersCollection.findOne({ authCodeHash });
    
    // Якщо не знайшли точний збіг хешу, шукаємо серед усіх користувачів
    // (для сумісності зі старими записами)
    if (!foundUser) {
      const users = await usersCollection.find({}).toArray();
      
      for (const user of users) {
        if (user.authCodeHash) {
          const isMatch = await bcrypt.compare(authCode, user.authCodeHash);
          if (isMatch) {
            foundUser = user;
            break;
          }
        }
      }
    }

    if (!foundUser) {
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
