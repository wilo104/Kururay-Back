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
// app.post('/login', async (req, res) => {
//   const { dni, password } = req.body;

//   try {
//     // Validar entrada
//     if (!dni || !password) {
//       return res.status(400).json({ message: 'Por favor, ingrese DNI y contraseña' });
//     }

//     // Realizar la autenticación en la base de datos
//     const userQuery = await pool.query('SELECT dni, password, tipo_usuario FROM usuarios WHERE dni = $1', [dni]);

//     if (userQuery.rows.length === 0) {
//       return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
//     }

//     const storedPasswordHash = userQuery.rows[0].password;

//     if (!(await bcrypt.compare(password, storedPasswordHash))) {
//       return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
//     }

//     // Generar el token JWT con un secreto seguro
//     const secretKey = process.env.JWT_SECRET_KEY || 'tu_secreto_secreto';
//     const token = jwt.sign({ dni: userQuery.rows[0].dni, role: userQuery.rows[0].role }, secretKey);

//     //Incluir el rol en la respuesta 
//     const tipo_usuario = userQuery.rows[0].tipo_usuario;

//     res.json({ token, tipo_usuario:tipo_usuario });
//   } catch (error) {
//     console.error('Error en la autenticación:', error);
//     res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
//   }
// });
app.post('/login', async (req, res) => {
  const { dni, password } = req.body;

  try {
    // Validar entrada
    if (!dni || !password) {
      return res.status(400).json({ message: 'Por favor, ingrese DNI y contraseña' });
    }

    // Realizar la autenticación en la base de datos
    // Asegúrate de incluir `id` en la selección de tu consulta SQL
    const userQuery = await pool.query('SELECT id, dni, password, tipo_usuario, estado_usuario FROM usuarios WHERE dni = $1', [dni]);

    if (userQuery.rows.length === 0) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    const storedPasswordHash = userQuery.rows[0].password;

    if (!(await bcrypt.compare(password, storedPasswordHash))) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Verificar el estado del usuario
    const estadoUsuario = userQuery.rows[0].estado_usuario;
    if (estadoUsuario === false) {
      return res.status(403).json({ message: 'Su cuenta se encuentra en estado de baja. Por favor, contacte al administrador.' });
    }

    // Generar el token JWT con un secreto seguro
    const secretKey = process.env.JWT_SECRET_KEY || 'tu_secreto_secreto';
    const token = jwt.sign({ dni: userQuery.rows[0].dni, role: userQuery.rows[0].role }, secretKey);

    // Incluir el rol y el ID en la respuesta
    const tipo_usuario = userQuery.rows[0].tipo_usuario;
    const id = userQuery.rows[0].id; // Obtener el ID del usuario de la consulta

    res.json({ token, tipo_usuario, id }); // Incluir el ID en la respuesta JSON
  } catch (error) {
    console.error('Error en la autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
  }
});

app.get('/usuarios', async (req, res) => {
  try {
      const result = await pool.query('SELECT * FROM usuarios');
      res.json(result.rows);
  } catch (error) {
      console.error('Error al obtener usuarios:', error);
      res.status(500).json({ message: 'Error en el servidor al obtener usuarios' });
  }
});
// Endpoint para obtener un usuario específico por ID
app.get('/usuarios/:id', async (req, res) => {
  const { id } = req.params; // Extrae el ID del parámetro de ruta

  try {
    // Realiza una consulta a la base de datos para obtener el usuario por su ID
    const result = await pool.query('SELECT * FROM usuarios WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      // Si no se encuentra el usuario, devuelve un error 404
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Si el usuario se encuentra, devuelve el usuario como respuesta JSON
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener el usuario por ID:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el usuario' });
  }
});

// Endpoint para redirigir a la pantalla de registro de usuarios desde la pantalla de listado de usuarios
app.get('/usuarios/registro', (req, res) => {
  // Redirigir a la pantalla de registro de usuarios
  res.redirect('/usuarios/registro');
});

// Endpoint para registrar un nuevo usuario
// app.post('/usuarios/registro', async (req, res) => {
//   const { dni, nombre, apellido_paterno, apellido_materno, password, correo, telefono, tipo_usuario } = req.body;

//   try {
//     // Validar campos
//     if (!dni || !nombre || !apellido_paterno || !password || !correo || !telefono || !tipo_usuario) {
//       return res.status(400).json({ message: 'Todos los campos son obligatorios' });
//     }

//     // Verificar si el usuario ya existe en la base de datos
//     const userExistsQuery = await pool.query('SELECT * FROM usuarios WHERE dni = $1', [dni]);
//     if (userExistsQuery.rows.length > 0) {
//       return res.status(400).json({ message: 'El usuario ya está registrado' });
//     }

//     // Hash de la contraseña antes de almacenarla en la base de datos
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Insertar el nuevo usuario en la base de datos
//     const insertQuery = await pool.query(
//       'INSERT INTO usuarios (dni, nombre, apellido_paterno, apellido_materno, password, correo, telefono, tipo_usuario, estado_usuario) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
//       [dni, nombre, apellido_paterno, apellido_materno, hashedPassword, correo, telefono, tipo_usuario, true]
//     );

//     // Redirigir a la pantalla de listado de usuarios con un mensaje de éxito
//     res.json({ message: 'Registrado correctamente' });
//   } catch (error) {
//     console.error('Error en el registro de usuario:', error);
//     res.status(500).json({ message: 'No es posible realizar el registro' });
//   }
// });


app.post('/usuarios/registro', async (req, res) => {
  const { dni, nombre, correo, telefono, tipo_usuario } = req.body;

  try {
    // Validar campos
    if (!nombre) {
      return res.status(400).json({ message: 'El nombre es obligatorio' });
    }

    if (!dni || dni.length !== 8 || !/^\d{8}$/.test(dni)) {
      return res.status(400).json({ message: 'El DNI debe ser de 8 dígitos numéricos y es obligatorio' });
    }

    if (!correo || !/\S+@\S+\.\S+/.test(correo)) {
      return res.status(400).json({ message: 'El correo es inválido o está vacío' });
    }

    if (!telefono || telefono.length !== 9 || !/^\d{9}$/.test(telefono)) {
      return res.status(400).json({ message: 'El teléfono debe ser de 9 dígitos numéricos y es obligatorio' });
    }

    if (!tipo_usuario) {
      return res.status(400).json({ message: 'El tipo de usuario es obligatorio' });
    }

    // Verificar si el usuario ya existe en la base de datos
    const userExistsQuery = await pool.query('SELECT * FROM usuarios WHERE dni = $1', [dni]);
    if (userExistsQuery.rows.length > 0) {
      return res.status(400).json({ message: 'El usuario ya está registrado' });
    }

    // Usar el DNI como clave inicial
    const hashedPassword = await bcrypt.hash(dni, 10);

    // Insertar el nuevo usuario en la base de datos
    const insertQuery = await pool.query(
      'INSERT INTO usuarios (dni, nombre, password, correo, telefono, tipo_usuario, estado_usuario) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [dni, nombre, hashedPassword, correo, telefono, tipo_usuario, true]
    );

    // Redirigir a la pantalla de listado de usuarios con un mensaje de éxito y mostrar modal
    res.json({ message: 'Registrado correctamente', modal: 'Registrado' });
  } catch (error) {
    console.error('Error en el registro de usuario:', error);
    res.status(500).json({ message: 'No es posible realizar el registro' });
  }
});

// Endpoint para redirigir a la pantalla de listado de usuarios desde la pantalla de registro de usuarios
app.get('/usuarios/listado', (req, res) => {
  // Redirigir a la pantalla de listado de usuarios
  res.redirect('/usuarios/listado');
});

//Endpoint para dar de alta o baja al usuario
app.put('/usuarios/:id/estado', async (req, res) => {
  const userId = req.params.id;
  const { nuevoEstado } = req.body; // Nuevo estado del usuario (baja o alta)

  try {
    // Verificar si el usuario existe en la base de datos
    const userQuery = await pool.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    const usuario = userQuery.rows[0];

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    let estadoUsuario;
    // Determinar el nuevo estado del usuario
    if (nuevoEstado === 'alta') {
      estadoUsuario = true;
    } else if (nuevoEstado === 'baja') {
      estadoUsuario = false;
    } else {
      return res.status(400).json({ message: 'El nuevo estado debe ser "alta" o "baja"' });
    }

    // Actualizar el estado del usuario
    await pool.query('UPDATE usuarios SET estado_usuario = $1 WHERE id = $2', [estadoUsuario, userId]);

    // Enviar respuesta exitosae
    res.json({ message: `El usuario ha sido marcado como "${nuevoEstado}"` });
  } catch (error) {
    console.error('Error al cambiar el estado del usuario:', error);
    res.status(500).json({ message: 'No es posible cambiar el estado del usuario' });
  }
});

// Endpoint para editar un usuario específico
app.put('/usuarios/:id', async (req, res) => {
  const userId = req.params.id;
  const { nombre, correo, telefono, tipo_usuario } = req.body;

  try {
    // Verificar si el usuario existe en la base de datos
    const userQuery = await pool.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    const usuario = userQuery.rows[0];

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Actualizar la información del usuario
    await pool.query(
      'UPDATE usuarios SET nombre = $1, correo = $2, telefono = $3, tipo_usuario = $4 WHERE id = $5',
      [nombre, correo, telefono, tipo_usuario, userId]
    );

    res.json({ message: 'Usuario actualizado correctamente' });
  } catch (error) {
    console.error('Error al editar usuario:', error);
    res.status(500).json({ message: 'Error al editar usuario' });
  }
});

app.put('/usuarios/:id/cambiar-contrasena', async (req, res) => {
  const userId = req.params.id;
  const { contrasenaActual, nuevaContrasena } = req.body;

  try {
    // Verificar si el usuario existe
    const userQuery = await pool.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    const usuario = userQuery.rows[0];

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña actual
    const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
    if (!contrasenaValida) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }

    // Hashear la nueva contraseña
    const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

    // Actualizar la contraseña en la base de datos
    await pool.query(
      'UPDATE usuarios SET password = $1 WHERE id = $2',
      [nuevaContrasenaHash, userId]
    );

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar la contraseña:', error);
    res.status(500).json({ message: 'Error al actualizar la contraseña' });
  }
});


// Otros endpoints para obtener información según el rol, etc.

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});