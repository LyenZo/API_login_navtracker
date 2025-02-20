const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const routes = require('./routes');

app.use(bodyParser.json());

// Rutas de la API
app.use('/api', routes);

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor API a la espera de consulta, por el puerto ${PORT}`);
});
