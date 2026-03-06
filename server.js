const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, name + ext);
    }
});
const upload = multer({ storage });

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'supersecretrecipekey123',
    resave: false,
    saveUninitialized: false,
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

const requireAuth = (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        const err = new Error('Access Denied. You are not an admin.');
        err.status = 403;
        return next(err);
    }
    next();
};

app.get('/', async (req, res, next) => {
    try {
        const query = req.query.q || '';
        let recipes;
        if (query) {
            recipes = await prisma.recipe.findMany({
                where: { title: { contains: query, mode: 'insensitive' } },
                include: { author: true },
                orderBy: { createdAt: 'desc' }
            });
        } else {
            recipes = await prisma.recipe.findMany({
                include: { author: true },
                orderBy: { createdAt: 'desc' }
            });
        }
        res.render('index', { recipes, query });
    } catch (err) {
        next(err);
    }
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res, next) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { username, password: hashedPassword, role: role === 'admin' ? 'admin' : 'user' }
        });
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.redirect('/');
    } catch (err) {
        if (err.code === 'P2002') {
            return next(new Error('Username already exists'));
        }
        next(err);
    }
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const user = await prisma.user.findUnique({ where: { username } });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/');
        } else {
            throw new Error('Invalid credentials');
        }
    } catch (err) {
        next(err);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/recipe/create', requireAuth, (req, res) => {
    res.render('create');
});

app.post('/recipe/create', requireAuth, upload.single('imageFile'), async (req, res, next) => {
    try {
        const { title, description, imageUrl } = req.body;
        let finalImageUrl = imageUrl || null;
        if (req.file) {
            finalImageUrl = '/public/uploads/' + req.file.filename;
        }
        await prisma.recipe.create({
            data: {
                title,
                description,
                imageUrl: finalImageUrl,
                authorId: req.session.user.id
            }
        });
        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

app.get('/recipe/:id', async (req, res, next) => {
    try {
        const id = parseInt(req.params.id);
        const recipe = await prisma.recipe.findUnique({
            where: { id },
            include: { author: true }
        });
        if (!recipe) throw new Error('Recipe not found');
        res.render('recipe', { recipe });
    } catch (err) {
        next(err);
    }
});

app.get('/recipe/:id/edit', requireAuth, async (req, res, next) => {
    try {
        const id = parseInt(req.params.id);
        const recipe = await prisma.recipe.findUnique({ where: { id } });
        if (!recipe) throw new Error('Recipe not found');
        if (recipe.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
            throw new Error('Unauthorized to edit this recipe');
        }
        res.render('edit', { recipe });
    } catch (err) {
        next(err);
    }
});

app.post('/recipe/:id/edit', requireAuth, upload.single('imageFile'), async (req, res, next) => {
    try {
        const id = parseInt(req.params.id);
        const recipe = await prisma.recipe.findUnique({ where: { id } });
        if (!recipe) throw new Error('Recipe not found');
        if (recipe.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
            throw new Error('Unauthorized');
        }

        const { title, description, imageUrl } = req.body;
        let finalImageUrl = imageUrl || recipe.imageUrl;
        if (req.file) {
            finalImageUrl = '/public/uploads/' + req.file.filename;
        }

        await prisma.recipe.update({
            where: { id },
            data: { title, description, imageUrl: finalImageUrl }
        });
        res.redirect(`/recipe/${id}`);
    } catch (err) {
        next(err);
    }
});

app.post('/recipe/:id/delete', requireAuth, async (req, res, next) => {
    try {
        const id = parseInt(req.params.id);
        const recipe = await prisma.recipe.findUnique({ where: { id } });
        if (!recipe) throw new Error('Recipe not found');
        if (recipe.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
            throw new Error('Unauthorized');
        }
        await prisma.recipe.delete({ where: { id } });
        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

app.get('/admin', requireAdmin, async (req, res, next) => {
    try {
        const users = await prisma.user.findMany({
            include: { _count: { select: { recipes: true } } }
        });
        const recipes = await prisma.recipe.findMany({
            include: { author: true },
            orderBy: { createdAt: 'desc' }
        });
        res.render('admin', { users, recipes });
    } catch (err) {
        next(err);
    }
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(err.status || 500);
    res.render('error', { error: err.stack, message: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});
