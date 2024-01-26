const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors'); // Importa el middleware cors

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Configura CORS para permitir solicitudes desde cualquier origen (*)
app.use(cors());

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bdKururay',
    password: 'alohomora',
    port: 5432,
});

// Endpoint para el inicio de sesión
app.post('/login', async (req, res) => {
  const { dni, password } = req.body;

  try {
    // Validar entrada
    if (!dni || !password) {
      return res.status(400).json({ message: 'Por favor, ingrese DNI y contraseña' });
    }

    // Realizar la autenticación en la base de datos
    const userQuery = await pool.query('SELECT dni, password, role FROM usuarios WHERE dni = $1', [dni]);

    if (userQuery.rows.length === 0) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    const storedPasswordHash = userQuery.rows[0].password;

    if (!(await bcrypt.compare(password, storedPasswordHash))) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Generar el token JWT con un secreto seguro
    const secretKey = process.env.JWT_SECRET_KEY || 'tu_secreto_secreto';
    const token = jwt.sign({ dni: userQuery.rows[0].dni, role: userQuery.rows[0].role }, secretKey);

    res.json({ token });
  } catch (error) {
    console.error('Error en la autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
  }
});

// Otros endpoints para obtener información según el rol, etc.

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});