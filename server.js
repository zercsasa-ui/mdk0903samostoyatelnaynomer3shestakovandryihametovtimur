const express = require('express');
const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');
const session = require('express-session');

//Пул с правильными настройками
const sequelize = new Sequelize({
    dialect: "sqlite",
    storage: "database.sqlite",
    logging: false,
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    },
    retry: {
        max: 3
    }
});

const app = express();

app.use(express.urlencoded());
app.use(express.json());
app.use('/img', express.static('img'));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

//использование ORM
const Users = sequelize.define(
    'User',
    {
        uid: { type: DataTypes.INTEGER, allowNull: false },
        nickname: { type: DataTypes.STRING, allowNull: false },
        name: { type: DataTypes.STRING },
        class: { type: DataTypes.STRING },
        algorithm: { type: DataTypes.STRING },
        description: { type: DataTypes.STRING },
        imgPathName: { type: DataTypes.STRING },
        role: { type: DataTypes.ENUM('admin', 'user'), defaultValue: 'user' },
        password: { type: DataTypes.STRING }
    }
)

app.get('/', (req, res) => {
    res.redirect('/main');
})

app.get('/main', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

app.get('/user/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/change', (req, res) => {
    if (req.session.user == null) res.redirect('/login');
    res.sendFile(path.join(__dirname, 'public', 'change.html'));
});

//WAF
const sqlInjectionPatterns = [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/gi,
    /(\b)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)(\b)/gi, 
    /(\b)(OR|AND)(\s+)(\d+)(\s*)=(\s*)(\d+)/gi,
    /(\b)(EXEC|EXECUTE|EXEC SP_)/gi,
];


app.post('/auth', async (req, res) => {
    try {
        const { nickname, password } = req.body;

        if (!nickname && !password) return res.status(401).json({ error: "Введите все данные" });

        for (pattern in sqlInjectionPatterns) { 
            if (pattern.test(nickname)) res.status(400).json({ error: "Введите настоящий никнейм" });
            if (pattern.test(password)) res.status(400).json({ error: "Введите настоящий пароль" });       
        }

        const curUser = await Users.findOne({ where: { nickname } });

        if (!curUser) return res.status(403).json({ error: "Нет такого пользователя" });

        if (curUser.password != password) return res.status(404).json({ error: "Неправильно введен пароль" });

        req.session.user = {
            uid: curUser.uid,
            nickname: curUser.nickname,
            role: curUser.role,
        }

        res.redirect(`/user/${curUser.uid}`);
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

//принцип наименьших привелегий
const checkUserRole = (req, res, next) => { 
    const user = req.session.user;
    if (user.role != 'user' || user.role != 'admin') res.status(401).json({ error: "Нет доступа" });
    
    next();
}

app.post('/changeProfile', checkUserRole, async (req, res) => {
    try {
        const { nickname, name, classs, algorithm, description, password } = req.body;

        const curUser = await Users.findOne({ where: { uid: req.session.user.uid } });

        curUser.update({
            nickname: nickname ? nickname : curUser.nickname,
            name: name ? name : curUser.name,
            class: classs ? classs : curUser.class,
            algorithm: algorithm ? algorithm : curUser.algorithm,
            description: description ? description : curUser.description,
            password: password ? password : curUser.password,
        });

        req.session.user = {
            uid: curUser.uid,
            nickname: nickname ?? curUser.nickname,
            role: curUser.user,
        }

        res.redirect(`/user/${curUser.uid}`);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
})

app.post('/logout', checkUserRole, async (req, res) => {
    try {
        req.session.user = null;

        res.redirect('/');
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

app.get('/api/users', async (req, res) => {
    const users = await Users.findAll();

    res.json(users);
})

app.get('/getUser/:uid', async (req, res) => {
    const uid = req.params.uid;
    const user = await Users.findOne({ where: { uid: uid } });

    res.json(user);
})

app.get('/getCurUser', async (req, res) => {
    const curuser = req.session.user;

    var user;
    if (curuser == null) user = null;
    else { user = await Users.findOne({ where: { uid: curuser.uid } }); }
    res.json(user);
})

app.listen(3000, async () => {
    await sequelize.authenticate();
    await sequelize.sync({ force: true });
    await createUsers();
    console.log('http://localhost:3000');
});

const createUsers = async () => {
    const uidA = Math.round(Math.random() * (999999 - 100000) + 100000);
    const andriy = await Users.create({
        uid: uidA,
        nickname: "Andriy",
        name: "Шестаков Андрей Максимович",
        class: "студент №28 в группе 4вб1",
        algorithm: "Что-то делает",
        description: "Умный человек в очках скачать обои",
        imgPathName: "Adnriy",
        role: "user",
        password: "andriy123"
    });
    const uidT = Math.round(Math.random() * (999999 - 100000) + 100000);
    const timur = await Users.create({
        uid: uidT,
        nickname: "Timur",
        name: "Хаметов Тимур Азатович",
        class: "студент группы 4вб1 №25",
        algorithm: "Что-то делает",
        description: "Клавиши тыкать до победного",
        imgPathName: "Timur",
        role: "user",
        password: "timur123"
    });
    const uidD = Math.round(Math.random() * (999999 - 100000) + 100000);
    const admin = await Users.create({
        uid: uidD,
        nickname: "Admin",
        name: "Админов Админ Админович",
        class: "какой-то админ сайта",
        algorithm: "администрирует сайт",
        description: "администратор сайта и он тут главный",
        imgPathName: "Admin",
        role: "admin",
        password: "admin123"
    });

    await andriy.save();
    await timur.save();
    await admin.save();
}