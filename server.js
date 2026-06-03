require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CONFIGURAÇÃO DA CONEXÃO COM SEU AZURE MYSQL via .env
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306),
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false
    }
});

db.connect(err => {
    if (err) throw err;
    console.log('Conectado ao MySQL no Azure!');
});

// Serve arquivos estáticos da pasta public
app.use(express.static(path.join(__dirname, '..', 'public')));

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const isValidExt = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const isValidMime = allowedTypes.test(file.mimetype);
        if (isValidExt && isValidMime) {
            cb(null, true);
        } else {
            cb(new Error('Apenas imagens JPEG, PNG ou GIF são permitidas.'));
        }
    }
});

// Endpoint para cadastrar aluno
app.post('/cadastrar', upload.single('foto'), async (req, res) => {
    const { nome, usuario, senha, email, observacao } = req.body;

    // Validação básica no servidor
    if (!nome || !usuario || !senha || !email) {
        return res.status(400).json({ erro: 'Campos obrigatórios ausentes!' });
    }

    try {
        // Criptografando a senha (bcrypt)
        const saltRounds = 10;
        const hash = await bcrypt.hash(senha, saltRounds);

        const sql = 'INSERT INTO alunos (nome_completo, usuario_acesso, senha_hash, email_aluno, observacao, foto) VALUES (?, ?, ?, ?, ?, ?)';
        const fotoBuffer = req.file ? req.file.buffer : null;

        db.query(sql, [nome, usuario, hash, email, observacao, fotoBuffer], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ erro: 'Usuário ou E-mail já existe!' });
                return res.status(500).json({ erro: 'Erro no banco de dados.' });
            }

            res.json({ mensagem: 'Aluno cadastrado com sucesso!' });
        });
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao processar senha.' });
    }
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ erro: err.message });
    }
    if (err) {
        return res.status(400).json({ erro: err.message || 'Erro ao processar arquivo.' });
    }
    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000'));