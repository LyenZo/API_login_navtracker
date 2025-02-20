require('dotenv').config(); 
const express = require('express');
const bcrypt = require('bcryptjs');  
const jwt = require('jsonwebtoken');
const router = express.Router();
const connection = require('./db');
const nodemailer = require('nodemailer');

const SECRET_KEY = process.env.JWT_SECRET || "clave_por_defecto"; 

router.get('/registros', (req, res) => {
    connection.query('SELECT * FROM usuario', (err, results) => {
        if (err) {
            console.error('Error al obtener registros:', err);
            return res.status(500).json({ error: 'Error al obtener registros' });
        }
        res.json(results);
    });
});

router.post('/registros', async (req, res) => {
    try {
        const { nombre, ap_pat, ap_mat, email, password, n_tel, id_tipo, id_vehiculo } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const vehiculoFinal = id_tipo === "2" ? "1" : id_vehiculo;

        const nuevoUsuario = { nombre, ap_pat, ap_mat, email, password: hashedPassword, n_tel, id_tipo, id_vehiculo: vehiculoFinal };

        connection.query('INSERT INTO usuario SET ?', nuevoUsuario, (err, results) => {
            if (err) {
                console.error('Error al crear un nuevo registro:', err);
                return res.status(500).json({ error: 'Error al crear un nuevo registro' });
            }
            res.status(201).json({ message: 'Registro creado exitosamente' });
        });
    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});


router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    connection.query('SELECT * FROM usuario WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Error al buscar usuario:', err);
            return res.status(500).json({ error: 'Error en el servidor' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const usuario = results[0];

        console.log("🔹 Usuario encontrado:", usuario.email);
        console.log("🔹 Contraseña ingresada:", password);
        console.log("🔹 Contraseña almacenada:", usuario.password);
        const passwordCorrecta = await bcrypt.compare(password, usuario.password);

        console.log("🔹 ¿Coincide la contraseña?", passwordCorrecta);

        if (!passwordCorrecta) {
            console.log("Contraseña incorrecta");
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        const token = jwt.sign(
            { id: usuario.id_u, email: usuario.email, id_tipo: usuario.id_tipo },
            SECRET_KEY,
            { expiresIn: '8h' }
        );

        res.json({ message: 'Login exitoso', token, usuario });
    });
});

router.post('/recuperar-password', (req, res) => {
    const { email } = req.body;

    connection.query('SELECT * FROM usuario WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error("Error en la búsqueda de usuario:", err);
            return res.status(500).json({ error: "Error en el servidor" });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: "Correo no registrado" });
        }

        const usuario = results[0];
        const token = jwt.sign({ id: usuario.id_u }, SECRET_KEY, { expiresIn: '1h' }); 

        
        const transporter = nodemailer.createTransport({
            service: "gmail",
            port: 456,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER, 
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Recuperación de contraseña",
            html: `<p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
                   <a href="http://localhost:5173/restablecer-password/${token}">Restablecer contraseña</a>
                   <p>Este enlace expirará en 1 hora.</p>`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error al enviar el correo:", error);
                return res.status(500).json({ error: "No se pudo enviar el correo" });
            }
            res.json({ message: "Correo enviado. Revisa tu bandeja de entrada." });
        });
    });
});

router.post('/restablecer-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        console.log("Hashed Password:", hashedPassword);
        console.log("id:", decoded.id);
        connection.query('UPDATE usuario SET password = ? WHERE id_u = ?', [hashedPassword, decoded.id], (err, results) => {
            if (err) {
                console.error("Error al actualizar contraseña:", err);
                return res.status(500).json({ error: "Error al actualizar la contraseña" });
            }
            res.json({ message: "Contraseña actualizada correctamente" });
        });
    } catch (error) {
        console.error("Error con el token:", error);
        return res.status(400).json({ error: "Token inválido o expirado" });
    }
});



//////////////////////////////////////////////////////////////////////////////////////////////7

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Acceso denegado, token requerido' });

    jwt.verify(token.split(' ')[1], SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

router.get('/perfil', authenticateToken, (req, res) => {
    const userId = req.user.id;
    connection.query('SELECT id_u, nombre, ap_pat, ap_mat, email, n_tel, id_tipo, id_vehiculo FROM usuario WHERE id_u = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener perfil:', err);
            return res.status(500).json({ error: 'Error al obtener el perfil' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json(results[0]);
    });
});
module.exports = router;
