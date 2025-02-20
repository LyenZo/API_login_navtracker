const express = require('express');
const router = express.Router();
const connection = require('./db');

router.get('/registros', (req, res) => {
  connection.query('SELECT * FROM tb_alumnos', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

router.get('/registros/:id', (req, res) => {
  connection.query('SELECT * FROM tb_alumnos WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

module.exports = router;
