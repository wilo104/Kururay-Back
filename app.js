const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bdKururay',
    password: 'alohomora',
    port: 5432,
});

app.post('/login', async (req, res) => {
  const { dni, password } = req.body;

  try {
    const userQuery = await pool.query('SELECT * FROM usuarios WHERE dni = $1', [dni]);

    if (userQuery.rows.length === 0 || !(await bcrypt.compare(password, userQuery.rows[0].password))) {
      return res.status(401).json({ message: 'Usuario o clave incorrecto' });
    }

    const token = jwt.sign({ dni: userQuery.rows[0].dni, role: userQuery.rows[0].role }, 'tu_secreto');

    res.json({ token });
  } catch (error) {
    console.error('Error en la autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});