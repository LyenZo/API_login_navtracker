const mysql = require('mysql');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'js_db'
});

connection.connect((err) => {
  if (err) {
    console.error('Error: conexión con la DB fallida: ', err);
    return;
  }
  console.log('Conexión exitosa con la DB');
});

module.exports = connection;