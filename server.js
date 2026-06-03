require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CONFIGURAÇÃO DA CONEXÃO COM O AZURE MYSQL
// Usa variáveis de ambiente se existirem, caso contrário usa valores padrão
const dbConfig = {
    host: process.env.DB_HOST || 'nickolas-server.mysql.database.azure.com',
    user: process.env.DB_USER || 'nickolas',
    password: process.env.DB_PASSWORD || 'admin@123456',
    database: process.env.DB_NAME || 'db_nickolas',
    port: Number(process.env.DB_PORT || 3306),
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false
    }
};

console.log('Database config:', {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database,
    port: dbConfig.port
});

const db = mysql.createConnection(dbConfig);

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

// Endpoint para login (verificar usuário e senha)
app.post('/login', async (req, res) => {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios.' });

    console.log('Login attempt for:', usuario);

    const sql = 'SELECT id_aluno AS id, nome_completo, usuario_acesso, senha_hash, email_aluno, observacao, foto FROM alunos WHERE usuario_acesso = ? OR email_aluno = ? LIMIT 1';
    db.query(sql, [usuario, usuario], async (err, results) => {
        if (err) {
            console.error('DB error on /login:', err);
            return res.status(500).json({ erro: 'Erro no banco de dados.' });
        }
        if (!results || results.length === 0) {
            console.log('Login failed: user not found for', usuario);
            return res.status(401).json({ erro: 'Usuário não encontrado.' });
        }

        const user = results[0];
        try {
            const match = await bcrypt.compare(senha, user.senha_hash);
            if (!match) {
                console.log('Login failed: invalid password for', usuario);
                return res.status(401).json({ erro: 'Senha inválida.' });
            }

            const getMimeType = (buffer) => {
                if (!buffer || buffer.length < 2) return null;
                if (buffer[0] === 0xff && buffer[1] === 0xd8) return 'image/jpeg';
                if (buffer[0] === 0x89 && buffer[1] === 0x50) return 'image/png';
                if (buffer[0] === 0x47 && buffer[1] === 0x49) return 'image/gif';
                return 'application/octet-stream';
            };

            const fotoData = user.foto ? `data:${getMimeType(user.foto)};base64,${user.foto.toString('base64')}` : null;
            const { senha_hash, foto, ...safeUser } = user;
            console.log('Login successful for', usuario);
            res.json({ sucesso: true, aluno: { ...safeUser, foto: fotoData } });
        } catch (e) {
            console.error('Error verifying password for', usuario, e);
            res.status(500).json({ erro: 'Erro ao verificar senha.' });
        }
    });
});

// Endpoint para listar alunos (útil para verificação rápida)
app.get('/alunos', (req, res) => {
    const sql = 'SELECT id_aluno AS id, nome_completo, usuario_acesso, email_aluno, observacao FROM alunos ORDER BY id_aluno DESC';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('DB error on /alunos:', err);
            return res.status(500).json({ erro: 'Erro ao buscar alunos.' });
        }
        res.json({ alunos: results });
    });
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