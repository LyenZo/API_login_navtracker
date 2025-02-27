require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const XLSX = require('xlsx');
const router = express.Router();
const connection = require('./db');
const nodemailer = require('nodemailer');

const SECRET_KEY = process.env.JWT_SECRET || "clave_por_defecto"; 

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Acceso denegado, token requerido' });

  jwt.verify(token.split(' ')[1], SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ error: 'Token inválido' });
      req.user = user;
      next();
  });
};

///////////////////////////////////////////////////////////////////////////////////////////////////
//USUARIO

router.get('/usuario', (req, res) => {
  connection.query('SELECT * FROM usuario', (err, results) => {
      if (err) {
          console.error('Error al obtener registros:', err);
          return res.status(500).json({ error: 'Error al obtener registros' });
      }
      res.json(results);
  });
});

router.get('/usuario/:id_u', (req, res) => {
  const id_u = req.params.id_u;

  connection.query('SELECT * FROM usuario WHERE id_u = ?', [id_u], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/usuario', async (req, res) => {
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

router.put('/usuario/:id_u', async (req, res) => {
  const id_u = req.params.id_u;
  let datosActualizados = req.body;

  try {
    if (datosActualizados.contraseña) {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(datosActualizados.contraseña, saltRounds);
      datosActualizados.contraseña = hashedPassword; 
    }

    connection.query(
      'UPDATE usuario SET ? WHERE id_u = ?',
      [datosActualizados, id_u],
      (err, results) => {
        if (err) {
          console.error('Error al actualizar el registro:', err);
          return res.status(500).json({ error: 'Error al actualizar el registro' });
        }
        res.json({ message: 'Registro actualizado exitosamente' });
      }
    );
  } catch (error) {
    console.error('Error al hashear la contraseña:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

router.delete('/usuario/:id_u', (req, res) => {
  const id_u = req.params.id_u;
  connection.query('DELETE FROM usuario WHERE id_u = ?', [id_u], (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      return res.status(500).json({ error: 'Error al eliminar el registro' });
    }

    if (results.affectedRows === 0) {
      // No se encontró ningún registro con ese ID
      return res.status(404).json({ error: 'Registro no encontrado' });
    }

    res.json({ message: 'Registro eliminado exitosamente' });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//TIPO DE USUARIO

router.get('/u_tipo', (req, res) => {
  connection.query('SELECT * FROM u_tipo', (err, results) => {
      if (err) {
          console.error('Error al obtener registros:', err);
          return res.status(500).json({ error: 'Error al obtener registros' });
      }
      res.json(results);
  });
});

router.get('/u_tipo/:id_tipo', (req, res) => {
  const id_tipo = req.params.id_tipo;

  connection.query('SELECT * FROM u_tipo WHERE id_tipo = ?', [id_tipo], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/u_tipo', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO u_tipo SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    res.status(201).json({ message: 'Registro creado exitosamente' });
  });
});

router.put('/u_tipo/:id_tipo', (req, res) => {
  const id_tipo = req.params.id_tipo;
  const datosActualizados = req.body;
  connection.query('UPDATE u_tipo SET ? WHERE id_tipo = ?', [datosActualizados, id_tipo], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    res.json({ message: 'Registro actualizado exitosamente' });
  });
});

router.delete('/u_tipo/:id_tipo', (req, res) => {
  const id_tipo = req.params.id_tipo;
  connection.query('DELETE FROM u_tipo WHERE id_tipo = ?', [id_tipo], (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      return res.status(500).json({ error: 'Error al eliminar el registro' });
    }

    if (results.affectedRows === 0) {
      // No se encontró ningún registro con ese ID
      return res.status(404).json({ error: 'Registro no encontrado' });
    }

    res.json({ message: 'Registro eliminado exitosamente' });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//VEHICULO

router.get('/vehiculo', (req, res) => {
  connection.query('SELECT * FROM vehiculo', (err, results) => {
      if (err) {
          console.error('Error al obtener registros:', err);
          return res.status(500).json({ error: 'Error al obtener registros' });
      }
      res.json(results);
  });
});

router.get('/vehiculo/:id_vehiculo', (req, res) => {
  const id_vehiculo = req.params.id_vehiculo;

  connection.query('SELECT * FROM vehiculo WHERE id_vehiculo = ?', [id_vehiculo], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/vehiculo', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO vehiculo SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    res.status(201).json({ message: 'Registro creado exitosamente' });
  });
});

router.put('/vehiculo/:id_vehiculo', (req, res) => {
  const id_vehiculo = req.params.id_vehiculo;
  const datosActualizados = req.body;
  connection.query('UPDATE vehiculo SET ? WHERE id_vehiculo = ?', [datosActualizados, id_vehiculo], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    res.json({ message: 'Registro actualizado exitosamente' });
  });
});

router.delete('/vehiculo/:id_vehiculo', (req, res) => {
  const id_vehiculo = req.params.id_vehiculo;
  connection.query('DELETE FROM vehiculo WHERE id_vehiculo = ?', [id_vehiculo], (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      return res.status(500).json({ error: 'Error al eliminar el registro' });
    }

    if (results.affectedRows === 0) {
      
      return res.status(404).json({ error: 'Registro no encontrado' });
    }

    res.json({ message: 'Registro eliminado exitosamente' });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//RUTA

router.get('/ruta', (req, res) => {
  connection.query('SELECT * FROM ruta', (err, results) => {
      if (err) {
          console.error('Error al obtener registros:', err);
          return res.status(500).json({ error: 'Error al obtener registros' });
      }
      res.json(results);
  });
});

router.get('/ruta/:id_ruta', (req, res) => {
  const id_ruta = req.params.id_ruta;

  connection.query('SELECT * FROM ruta WHERE id_ruta = ?', [id_ruta], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/ruta', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO ruta SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    res.status(201).json({ message: 'Registro creado exitosamente' });
  });
});

router.put('/ruta/:id_ruta', (req, res) => {
  const id_ruta = req.params.id_ruta;
  const datosActualizados = req.body;
  connection.query('UPDATE ruta SET ? WHERE id_ruta = ?', [datosActualizados, id_ruta], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    res.json({ message: 'Registro actualizado exitosamente' });
  });
});


router.delete('/ruta/:id_ruta', (req, res) => {
  const id_ruta = req.params.id_ruta;
  connection.query('DELETE FROM ruta WHERE id_ruta = ?', [id_ruta], (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      return res.status(500).json({ error: 'Error al eliminar el registro' });
    }

    if (results.affectedRows === 0) {
      // No se encontró ningún registro con ese ID
      return res.status(404).json({ error: 'Registro no encontrado' });
    }

    res.json({ message: 'Registro eliminado exitosamente' });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//RASTREO

router.get('/rastreo', (req, res) => {
  connection.query('SELECT * FROM rastreo', (err, results) => {
      if (err) {
          console.error('Error al obtener registros:', err);
          return res.status(500).json({ error: 'Error al obtener registros' });
      }
      res.json(results);
  });
});

router.get('/rastreo/:id_rastreo', (req, res) => {
  const id_rastreo = req.params.id_rastreo;

  connection.query('SELECT * FROM rastreo WHERE id_rastreo = ?', [id_rastreo], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/rastreo', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO rastreo SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    res.status(201).json({ message: 'Registro creado exitosamente' });
  });
});

router.put('/rastreo/:id_rastreo', (req, res) => {
  const id_rastreo = req.params.id_rastreo;
  const datosActualizados = req.body;
  connection.query('UPDATE rastreo SET ? WHERE id_rastreo = ?', [datosActualizados, id_rastreo], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    res.json({ message: 'Registro actualizado exitosamente' });
  });
});


router.delete('/rastreo/:id_rastreo', (req, res) => {
  const id_ruta = req.params.id_ruta;
  connection.query('DELETE FROM rastreo WHERE id_rastreo = ?', [id_rastreo], (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      return res.status(500).json({ error: 'Error al eliminar el registro' });
    }

    if (results.affectedRows === 0) {
      // No se encontró ningún registro con ese ID
      return res.status(404).json({ error: 'Registro no encontrado' });
    }

    res.json({ message: 'Registro eliminado exitosamente' });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//PUNTOS DE RUTA

router.get('/punto_ruta', (req, res) => {
    connection.query('SELECT * FROM punto_ruta', (err, results) => {
        if (err) {
            console.error('Error al obtener registros:', err);
            return res.status(500).json({ error: 'Error al obtener registros' });
        }
        res.json(results);
    });
});

router.get('/punto_ruta/:id_punto', (req, res) => {
  const id_punto = req.params.id_punto;

  connection.query('SELECT * FROM punto_ruta WHERE id_punto = ?', [id_punto], (err, results) => {
      if (err) {
          console.error('Error al obtener el registro:', err);
          return res.status(500).json({ error: 'Error al obtener el registro' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Registro no encontrado' });
      }

      res.json(results[0]);
  });
});

router.post('/punto_ruta', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO punto_ruta SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    res.status(201).json({ message: 'Registro creado exitosamente' });
  });
});

  router.put('/punto_ruta/:id_punto', (req, res) => {
    const id_punto = req.params.id_punto;
    const datosActualizados = req.body;
    connection.query('UPDATE punto_ruta SET ? WHERE id_punto = ?', [datosActualizados, id_punto], (err, results) => {
      if (err) {
        console.error('Error al actualizar el registro:', err);
        res.status(500).json({ error: 'Error al actualizar el registro' });
        return;
      }
      res.json({ message: 'Registro actualizado exitosamente' });
    });
  });

  router.delete('/punto_ruta/:id_punto', (req, res) => {
    const id_punto = req.params.id_punto;
    connection.query('DELETE FROM punto_ruta WHERE id_punto = ?', [id_punto], (err, results) => {
      if (err) {
        console.error('Error al eliminar el registro:', err);
        return res.status(500).json({ error: 'Error al eliminar el registro' });
      }
  
      if (results.affectedRows === 0) {
        // No se encontró ningún registro con ese ID
        return res.status(404).json({ error: 'Registro no encontrado' });
      }
  
      res.json({ message: 'Registro eliminado exitosamente' });
    });
  });

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//LOGIN

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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//RECUPERAR CONTRASEÑA

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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//PERFIL

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
