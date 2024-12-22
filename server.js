require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// ===========================
// Middleware
// ===========================
app.use(bodyParser.json());
app.use(cors());

// ===========================
// Configuración de la base de datos
// ===========================
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

db.connect(err => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err.message);
        process.exit(1);
    }
    console.log('Conectado a la base de datos MySQL.');
});

// ===========================
// Middleware para validación de roles
// ===========================
function verificarToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: "No se proporcionó un token" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
        req.usuario = user;
        next();
    });
}

function verificarRol(roles) {
    return (req, res, next) => {
        const userRole = req.usuario?.rol;
        if (!userRole || !roles.includes(userRole)) {
            return res.status(403).json({ message: 'Acceso denegado: No tienes el rol adecuado.' });
        }
        next();
    };
}

// ===========================
// Rutas
// ===========================

// Registro de usuarios
app.post('/register', async (req, res) => {
    const { nombre, apellido, club, telefono, correo, usuario, contraseña, rol } = req.body;

    if (!nombre || !apellido || !club || !telefono || !correo || !usuario || !contraseña || !rol) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(contraseña, salt);

        const query = `INSERT INTO usuarios (nombre, apellido, club, telefono, correo, usuario, contraseña, rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        db.query(query, [nombre, apellido, club, telefono, correo, usuario, hashedPassword, rol], (err) => {
            if (err) return res.status(500).json({ message: 'Error al registrar el usuario', error: err });
            res.status(201).json({ message: 'Usuario registrado exitosamente' });
        });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error });
    }
});

// Inicio de sesión
app.post('/login', (req, res) => {
    const { usuario, contraseña, rol } = req.body;

    if (!usuario || !contraseña || !rol) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    const query = `SELECT * FROM usuarios WHERE usuario = ? AND rol = ?`;
    db.query(query, [usuario, rol], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor', error: err });

        if (results.length === 0) {
            return res.status(404).json({ message: 'Usuario o rol incorrecto' });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(contraseña, user.contraseña);
        if (!isMatch) {
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        const token = jwt.sign(
            { id: user.id, usuario: user.usuario, rol: user.rol },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.status(200).json({ 
            message: 'Inicio de sesión exitoso', 
            token, 
            rol: user.rol 
        });
    });
});

// Crear un torneo
app.post('/torneos', verificarToken, verificarRol(['organizador']), (req, res) => {
    const { nombre, club, participantes, pistas, grupos, fecha } = req.body;

    if (!nombre || !club || !participantes || !pistas || !grupos || !fecha) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    const query = `INSERT INTO torneos (nombre, club, participantes, pistas, grupos, fecha) VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(query, [nombre, club, participantes, pistas, grupos, fecha], (err, result) => {
        if (err) {
            console.error('Error al crear torneo:', err);
            return res.status(500).json({ message: 'Error al crear el torneo.' });
        }
        res.status(201).json({ message: 'Torneo creado exitosamente.', torneoId: result.insertId });
    });
});

// Obtener torneos
app.get('/torneos', (req, res) => {
    const query = 'SELECT * FROM torneos';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error al obtener los torneos', error: err });
        res.status(200).json(results);
    });
});

// Agregar participante
app.post('/participantes', verificarToken, verificarRol(['organizador']), (req, res) => {
    const { torneoId, nombre, apellido, telefono, correo, club } = req.body;

    if (!torneoId || !nombre || !apellido || !telefono || !correo || !club) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    const query = `INSERT INTO participantes (torneoId, nombre, apellido, telefono, correo, club) VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(query, [torneoId, nombre, apellido, telefono, correo, club], (err) => {
        if (err) {
            console.error('Error al agregar participante:', err);
            return res.status(500).json({ message: 'Error al agregar el participante.' });
        }
        res.status(201).json({ message: 'Participante agregado exitosamente.' });
    });
});

// Obtener participantes
app.get('/participantes', (req, res) => {
    const { torneoId } = req.query;

    if (!torneoId) {
        return res.status(400).json({ message: 'El ID del torneo es obligatorio' });
    }

    const query = 'SELECT * FROM participantes WHERE torneoId = ?';
    db.query(query, [torneoId], (err, results) => {
        if (err) {
            console.error('Error al obtener participantes:', err);
            return res.status(500).json({ message: 'Error al obtener participantes' });
        }
        res.status(200).json(results);
    });
});

// ===========================
// Manejo de errores global
// ===========================
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Error interno del servidor', error: err });
});

// ===========================
// Iniciar el servidor
// ===========================
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
});


