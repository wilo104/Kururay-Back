require('dotenv').config();  // Cargar variables de entorno

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const util = require('util');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3000;

// Seguridad con Helmet
app.use(helmet());

// Middleware
app.use(bodyParser.json());
app.use(cors());  // Permitir solicitudes desde cualquier origen (ajustar en producción)

// Conexión a PostgreSQL con manejo de errores
// const pool = new Pool({
//   user: process.env.DB_USER,
//   host: process.env.DB_HOST,
//   database: process.env.DB_DATABASE,
//   password: process.env.DB_PASSWORD,
//   port: process.env.DB_PORT,
//   max: 30,  // Máximo 30 conexiones simultáneas
//   idleTimeoutMillis: 30000,  // Cierra conexiones inactivas
//   connectionTimeoutMillis: 2000,  // Tiempo máximo de espera
// });
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Usa la URL completa proporcionada por Heroku
  ssl: {
    rejectUnauthorized: false, // Necesario para la conexión con Heroku Postgres
  },
});


pool.connect()
  .then(() => console.log('✅ Base de datos conectada correctamente'))
  .catch(err => console.error('❌ Error al conectar con la base de datos:', err));

// Configuración de Multer para subir archivos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, path.join(__dirname, 'uploads/'));
  },
  filename: function (req, file, cb) {
      cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Lectura de archivos asíncrona
const readFileAsync = util.promisify(fs.readFile);

// Servir archivos estáticos (solo si existen)
const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) {
    app.use(express.static(publicPath));
    app.get('*', (req, res) => {
        res.sendFile(path.join(publicPath, 'index.html'));
    });
}

// Middleware global de manejo de errores (debe ir al final)
app.use((err, req, res, next) => {
  console.error('❌ Error en el servidor:', err.stack);
  res.status(500).json({ message: 'Ocurrió un error en el servidor' });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`);
});

app.get('/', (req, res) => {
  res.send('¡Bienvenido a mi API!');
});


app.post('/login', async (req, res) => {
  const { dni, password } = req.body;

  try {
    if (!dni || !password) {
      return res.status(400).json({ message: 'Ingrese DNI y contraseña' });
    }

    let userQuery = await pool.query(
      `SELECT id, dni, password, tipo_usuario, estado_usuario,
      (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo
      FROM usuarios WHERE dni = $1`,
      [dni]
    );

    let isVoluntario = false;

    if (userQuery.rows.length === 0) {
      userQuery = await pool.query(
        `SELECT id, dni, password,
        (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo
        FROM voluntarios WHERE dni = $1`,
        [dni]
      );

      isVoluntario = true;

      if (userQuery.rows.length === 0) {
        return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
      }
    }

    const storedPasswordHash = userQuery.rows[0].password;

    if (!(await bcrypt.compare(password, storedPasswordHash))) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    const isClaveDni = await bcrypt.compare(dni, storedPasswordHash);
    const token = jwt.sign(
      {
        id: userQuery.rows[0].id,
        dni: userQuery.rows[0].dni,
        tipo_usuario: isVoluntario ? 'VOLUNTARIO' : userQuery.rows[0].tipo_usuario,
      },
      process.env.JWT_SECRET || 'default_secret', // Usar un valor por defecto seguro
      { expiresIn: '1h' } // Configurar expiración del token
    );

    // console.log(`Usuario ${dni} debe cambiar su contraseña: ${isClaveDni}`);

    return res.json({
      token,
      tipo_usuario: isVoluntario ? 'VOLUNTARIO' : userQuery.rows[0].tipo_usuario,
      id: userQuery.rows[0].id,
      nombre_completo: userQuery.rows[0].nombre_completo,
      clave_dni: isClaveDni,
    });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor durante el login' });
  }
});


// app.post('/login', async (req, res) => {
//   const { dni, password } = req.body;

//   try {
//     if (!dni || !password) {
//       return res.status(400).json({ message: 'Ingrese DNI y contraseña' });
//     }

//     // Consultar en la tabla usuarios
//     let userQuery = await pool.query(
//       `SELECT id, dni, password, tipo_usuario, estado_usuario,
//       (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo
//       FROM usuarios WHERE dni = $1`,
//       [dni]
//     );

//     if (userQuery.rows.length === 0) {
//       // Si no se encuentra en `usuarios`, buscar en `voluntarios`
//       userQuery = await pool.query(
//         `SELECT id, dni, password,
//         (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo
//         FROM voluntarios WHERE dni = $1`,
//         [dni]
//       );

//       if (userQuery.rows.length === 0) {
//         return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
//       }

//       const storedPasswordHash = userQuery.rows[0].password;

//       // Comparar contraseñas
//       if (!(await bcrypt.compare(password, storedPasswordHash))) {
//         return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
//       }

//       // Generar token JWT para voluntario
//       const token = jwt.sign(
//         {
//           id: userQuery.rows[0].id,
//           dni: userQuery.rows[0].dni,
//           tipo_usuario: 'VOLUNTARIO',
//         },
//         process.env.JWT_SECRET || 'process.env.JWT_SECRET'
//       );

//       return res.json({
//         token,
//         tipo_usuario: 'VOLUNTARIO',
//         id: userQuery.rows[0].id,
//         nombre_completo: userQuery.rows[0].nombre_completo, // Nombre completo del voluntario
//       });
//     }

//     // Si el usuario está en la tabla `usuarios`, verificar contraseña
//     const storedPasswordHash = userQuery.rows[0].password;

//     if (!(await bcrypt.compare(password, storedPasswordHash))) {
//       return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
//     }

//     if (!userQuery.rows[0].estado_usuario) {
//       return res.status(403).json({ message: 'Cuenta inactiva. Contacte al administrador.' });
//     }

//     // Generar token JWT para usuario
//     const token = jwt.sign(
//       {
//         id: userQuery.rows[0].id,
//         dni: userQuery.rows[0].dni,
//         tipo_usuario: userQuery.rows[0].tipo_usuario,
//       },
//       process.env.JWT_SECRET || 'process.env.JWT_SECRET'
//     );

//     res.json({
//       token,
//       tipo_usuario: userQuery.rows[0].tipo_usuario,
//       id: userQuery.rows[0].id,
//       nombre_completo: userQuery.rows[0].nombre_completo, // Nombre completo del usuario
//     });
//   } catch (error) {
//     console.error('Error en la autenticación:', error);
//     res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
//   }
// });




// *************SECCION USUARIOS****************

// Obtener lista de usuarios
app.get('/usuarios', async (req, res) => {
  try {
      const result = await pool.query('SELECT *FROM usuarios ORDER BY id ASC');
      res.json(result.rows);
  } catch (error) {
      console.error('Error al obtener usuarios:', error.message);
      res.status(500).json({ message: 'Error en el servidor al obtener usuarios' });
  }
});

// Obtener usuario por ID
app.get('/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  try {
      const result = await pool.query('SELECT * FROM usuarios WHERE id = $1', [id]);
      if (result.rows.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

      res.json(result.rows[0]);
  } catch (error) {
      console.error('Error al obtener usuario por ID:', error);
      res.status(500).json({ message: 'Error en el servidor al obtener el usuario' });
  }
});
app.post('/usuarios/registro', upload.single('cv'), async (req, res) => {
  const {
    dni,
    nombre,
    apellido_paterno,
    apellido_materno,
    correo,
    telefono,
    tipo_usuario,
  } = req.body; // `req.body` contiene los campos enviados



  try {
    if (!dni || !nombre || !apellido_paterno || !apellido_materno || !correo) {
      return res.status(400).json({ message: 'Faltan datos obligatorios' });
    }

    // Verificar si el usuario ya existe
    const existingUser = await pool.query('SELECT id FROM usuarios WHERE dni = $1', [dni]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'El usuario ya está registrado' });
    }

    // Generar el hash del DNI como contraseña inicial
    const hashedPassword = await bcrypt.hash(dni, 10);

    // Insertar el usuario en la base de datos
    const query = `
      INSERT INTO usuarios (
        dni, nombre, apellido_paterno, apellido_materno, correo, telefono, tipo_usuario, password
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8
      ) RETURNING *;
    `;
    const values = [
      dni, nombre, apellido_paterno, apellido_materno, correo, telefono, tipo_usuario, hashedPassword,
    ];

    const result = await pool.query(query, values);

    // Si hay un archivo, puedes guardarlo en otra tabla o procesarlo aquí
    if (req.file) {

      // Por ejemplo, guardar la ruta del archivo en la base de datos
    }

    res.status(201).json({ message: 'Usuario registrado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ message: 'Error en el servidor al registrar el usuario' });
  }
});
// app.put('/usuarios/:id/cambiar-contrasena', authenticateToken, async (req, res) => {
//   const userId = parseInt(req.params.id); // ID del usuario pasado en la URL
//   const { contrasenaActual, nuevaContrasena } = req.body;

//   try {
//     // Verificar si el usuario autenticado es el mismo que el que intenta cambiar la contraseña
//     if (req.user.id !== userId) {
//       return res.status(403).json({ message: 'No tiene permisos para cambiar esta contraseña' });
//     }

//     // Verificar si el usuario existe
//     const userQuery = await pool.query('SELECT password FROM usuarios WHERE id = $1', [userId]);
//     const usuario = userQuery.rows[0];

//     if (!usuario) {
//       return res.status(404).json({ message: 'Usuario no encontrado' });
//     }

//     // Verificar la contraseña actual
//     const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
//     if (!contrasenaValida) {
//       return res.status(401).json({ message: 'Contraseña actual incorrecta' });
//     }

//     // Generar el hash de la nueva contraseña
//     const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

//     // Actualizar la contraseña
//     await pool.query('UPDATE usuarios SET password = $1 WHERE id = $2', [nuevaContrasenaHash, userId]);
//     res.json({ message: 'Contraseña actualizada correctamente' });
//   } catch (error) {
//     console.error('Error al cambiar contraseña:', error);
//     res.status(500).json({ message: 'Error al cambiar la contraseña' });
//   }
// });

app.put('/cambiar-contrasena', authenticateToken, async (req, res) => {
  const { contrasenaActual, nuevaContrasena } = req.body;

  try {
    // Verificar si faltan datos
    if (!req.user || !contrasenaActual || !nuevaContrasena) {
      return res.status(400).json({ message: 'Datos incompletos' });
    }

    const { id, tipo_usuario } = req.user; // ID y tipo de usuario del token JWT

    // Definir la tabla en función del tipo de usuario
    const tabla = tipo_usuario === 'VOLUNTARIO' ? 'voluntarios' : 'usuarios';

    // Buscar al usuario o voluntario en la tabla correspondiente
    const query = `SELECT password FROM ${tabla} WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const usuario = result.rows[0];

    // Verificar la contraseña actual
    const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
    if (!contrasenaValida) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }

    // Generar el hash de la nueva contraseña
    const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

    // Actualizar la contraseña en la tabla correspondiente
    const updateQuery = `UPDATE ${tabla} SET password = $1 WHERE id = $2`;
    await pool.query(updateQuery, [nuevaContrasenaHash, id]);

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error al cambiar contraseña:', error.message || error);
    res.status(500).json({ message: 'Error en el servidor al cambiar la contraseña' });
  }
});



// Endpoint para redirigir a la pantalla de listado de usuarios desde la pantalla de registro de usuarios
app.get('/usuarios/listado', (req, res) => {
  // Redirigir a la pantalla de listado de usuarios
  res.redirect('/usuarios/listado');
});

// Ruta para actualizar usuarios
app.put('/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const fields = req.body;

  try {
    // Verificar si el usuario existe
    const query = `SELECT * FROM usuarios WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Construir la consulta de actualización dinámicamente
    const setFields = Object.keys(fields)
      .map((key, index) => `${key} = $${index + 1}`)
      .join(', ');
    const values = Object.values(fields);

    const updateQuery = `UPDATE usuarios SET ${setFields} WHERE id = $${values.length + 1}`;
    await pool.query(updateQuery, [...values, id]);

    res.json({ message: 'Usuario actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    res.status(500).json({ message: 'Error al actualizar usuario' });
  }
});

app.patch('/usuarios/:id/estado', authenticateToken, async (req, res) => {
  const { id } = req.params; // ID del usuario desde los parámetros
  const { estado_usuario } = req.body; // Estado enviado en el cuerpo de la solicitud

  if (typeof estado_usuario !== 'boolean') {
    return res.status(400).json({ message: 'El valor de estado_usuario debe ser booleano (true o false).' });
  }

  try {
    const query = `
      UPDATE usuarios
      SET estado_usuario = $1
      WHERE id = $2
      RETURNING *;
    `; // Actualizamos el campo `estado_usuario` en la tabla `usuarios`

    const result = await pool.query(query, [estado_usuario, id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    res.status(200).json({
      message: `Estado cambiado a ${estado_usuario ? 'ACTIVO' : 'INACTIVO'}`,
      usuario: result.rows[0] // Devuelve el usuario actualizado como respuesta
    });
  } catch (error) {
    console.error('Error al cambiar el estado del usuario:', error);
    res.status(500).json({ message: 'Error en el servidor al cambiar estado.' });
  }
});




// *************SECCION VOLUNTARIOS ****************

// app.get('/voluntarios', async (req, res) => {
//   try {
//     const query = `
//       SELECT *FROM voluntarios
//     `;
//     const result = await pool.query(query);

//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: 'No se encontraron voluntarios' });
//     }

//     res.status(200).json(result.rows);
//   } catch (error) {
//     console.error('Error al obtener voluntarios:', error);
//     res.status(500).json({ message: 'Error en el servidor al obtener los voluntarios' });
//   }
// });
app.get('/voluntarios', async (req, res) => {
  try {
    const query = `
      SELECT id, apellido_paterno, apellido_materno, nombre, dni, correo, celular, estado_voluntario 
      FROM voluntarios
    `;
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontraron voluntarios' });
    }

    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error al obtener voluntarios:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener los voluntarios' });
  }
});


app.get('/voluntarios/:id/cv', async (req, res) => {
  const voluntarioId = req.params.id;
  try {
      const result = await pool.query('SELECT cv FROM voluntarios WHERE id = $1', [voluntarioId]);
      if (result.rows.length === 0) return res.status(404).json({ message: 'Voluntario no encontrado o sin CV' });

      const cvBuffer = result.rows[0].cv;
      res.setHeader('Content-Type', 'application/pdf');
      res.send(cvBuffer);
  } catch (error) {
      console.error('Error al obtener el CV del voluntario:', error);
      res.status(500).json({ message: 'Error al obtener el CV del voluntario' });
  }
});

app.get('/voluntarios/:id', authenticateToken, async (req, res) => {
const { id } = req.params;
try {
  const result = await pool.query('SELECT * FROM voluntarios WHERE id = $1', [id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ message: 'Voluntario no encontrado' });
  }
  res.status(200).json(result.rows[0]);
} catch (error) {
  console.error('Error al obtener detalle del voluntario:', error);
  res.status(500).json({ message: 'Error al obtener detalle del voluntario' });
}
});

app.get('/voluntarios/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM voluntarios WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener detalle del voluntario:', error);
    res.status(500).json({ message: 'Error al obtener detalle del voluntario' });
  }
});

// app.put('/voluntarios/:id/cambiar-contrasena', authenticateToken, async (req, res) => {
//   const voluntarioId = parseInt(req.params.id); // ID del voluntario pasado en la URL
//   const { contrasenaActual, nuevaContrasena } = req.body;

//   try {
//     // Verificar si el voluntario autenticado es el mismo que intenta cambiar la contraseña
//     if (req.user.id !== voluntarioId) {
//       return res.status(403).json({ message: 'No tiene permisos para cambiar esta contraseña' });
//     }

//     // Verificar si el voluntario existe
//     const voluntarioQuery = await pool.query('SELECT password FROM voluntarios WHERE id = $1', [voluntarioId]);
//     const voluntario = voluntarioQuery.rows[0];

//     if (!voluntario) {
//       return res.status(404).json({ message: 'Voluntario no encontrado' });
//     }

//     // Verificar la contraseña actual
//     const contrasenaValida = await bcrypt.compare(contrasenaActual, voluntario.password);
//     if (!contrasenaValida) {
//       return res.status(401).json({ message: 'Contraseña actual incorrecta' });
//     }

//     // Generar el hash de la nueva contraseña
//     const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

//     // Actualizar la contraseña en la base de datos
//     await pool.query('UPDATE voluntarios SET password = $1 WHERE id = $2', [nuevaContrasenaHash, voluntarioId]);

//     res.json({ message: 'Contraseña actualizada correctamente' });
//   } catch (error) {
//     console.error('Error al cambiar la contraseña del voluntario:', error);
//     res.status(500).json({ message: 'Error en el servidor al cambiar la contraseña del voluntario' });
//   }
// });

app.get('/voluntarios/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM voluntarios WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener detalle del voluntario:', error);
    res.status(500).json({ message: 'Error al obtener detalle del voluntario' });
  }
});

app.post('/voluntarios/registro', upload.single('cv'), async (req, res) => {
  const {
    dni,
    nombre,
    apellido_paterno,
    apellido_materno,
    correo,
    ciudad_residencia,
    celular,
    tipo_voluntariado,
    fecha_ingreso,
    fecha_nacimiento,
    area,
    rol,
    categoria,
    grado_instruccion,
    carrera,
    instagram,
    facebook,
    linkedin,
    especializacion,
    tema_especializacion,
  } = req.body;

  const cvFile = req.file ? req.file.path : null; // Ruta del archivo CV en el servidor



  try {
    // Validar campos obligatorios
    const erroresValidacion = [];
    if (!dni || dni.length !== 8 || !/^\d{8}$/.test(dni)) {
      erroresValidacion.push('El DNI debe ser de 8 dígitos numéricos y es obligatorio.');
    }
    if (!nombre) erroresValidacion.push('El nombre es obligatorio.');
    if (!apellido_paterno) erroresValidacion.push('El apellido paterno es obligatorio.');
    if (!correo) erroresValidacion.push('El correo es obligatorio.');

    if (erroresValidacion.length > 0) {
      return res.status(400).json({ message: 'Errores de validación', errors: erroresValidacion });
    }

    // Verificar si el voluntario ya existe
    const existingVoluntario = await pool.query('SELECT id FROM voluntarios WHERE dni = $1', [dni]);
    if (existingVoluntario.rows.length > 0) {
      return res.status(400).json({ message: 'El voluntario ya está registrado.' });
    }

    // Generar el hash del DNI como contraseña inicial
    const hashedPassword = await bcrypt.hash(dni, 10);

    // Generar código de voluntario
    const fechaIngresoYear = fecha_ingreso ? new Date(fecha_ingreso).getFullYear() : '0000';
    const categoriaAbbreviation = categoria ? categoria.substring(0, 3).toUpperCase() : 'N/A';
    const areaAbbreviation = area ? area.substring(0, 3).toUpperCase() : 'N/A';
    const codigo = `${fechaIngresoYear}_${categoriaAbbreviation}_${areaAbbreviation}`;

    // Leer el archivo CV como un búfer de bytes
    let cvBuffer = null;
    if (cvFile) {
      cvBuffer = await readFileAsync(cvFile);
    }

    // Consulta de inserción
    const query = `
      INSERT INTO voluntarios (
        dni, nombre, apellido_paterno, apellido_materno, correo, ciudad_residencia, celular,
        tipo_voluntariado, fecha_ingreso, fecha_nacimiento, area, rol, categoria,
        grado_instruccion, carrera, instagram, facebook, linkedin, codigo, cv, especializacion,
        tema_especializacion, estado_voluntario, password
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
      ) RETURNING *;
    `;

    const values = [
      dni,
      nombre,
      apellido_paterno,
      apellido_materno,
      correo,
      ciudad_residencia || null,
      celular || null,
      tipo_voluntariado || null,
      fecha_ingreso ? new Date(fecha_ingreso) : null,
      fecha_nacimiento ? new Date(fecha_nacimiento) : null,
      area || null,
      rol || null,
      categoria || null,
      grado_instruccion || null,
      carrera || null,
      instagram || null,
      facebook || null,
      linkedin || null,
      codigo,
      cvBuffer,
      especializacion || false,
      tema_especializacion || null,
      true, // estado_voluntario por defecto activo
      hashedPassword, // Contraseña encriptada
    ];

    const result = await pool.query(query, values);

    res.status(201).json({ message: 'Voluntario registrado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar voluntario:', error.message || error);
    res.status(500).json({ message: 'Error en el servidor al registrar el voluntario.' });
  }
});


app.get('/voluntarios/:id/cv', async (req, res) => {
  const voluntarioId = req.params.id;
  try {
    const result = await pool.query('SELECT cv FROM voluntarios WHERE id = $1', [voluntarioId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado o sin CV' });
    }

    const cvBuffer = result.rows[0].cv;
    res.setHeader('Content-Type', 'application/pdf');
    res.send(cvBuffer);
  } catch (error) {
    console.error('Error al obtener el CV del voluntario:', error);
    res.status(500).json({ message: 'Error al obtener el CV del voluntario.' });
  }
});

app.put('/voluntarios/:id', upload.single('cv'), async (req, res) => {
  const voluntarioId = req.params.id;
  const {
    nombre,
    apellido_paterno,
    apellido_materno,
    correo,
    celular,
    categoria,
    grado_instruccion,
    area,
    rol,
    carrera,
  } = req.body;

  const cvFile = req.file ? req.file.path : null;

  try {
    const query = `
      UPDATE voluntarios
      SET
        nombre = $1,
        apellido_paterno = $2,
        apellido_materno = $3,
        correo = $4,
        celular = $5,
        categoria = $6,
        grado_instruccion = $7,
        area = $8,
        rol = $9,
        carrera = $10,
        cv = COALESCE($11, cv)
      WHERE id = $12
      RETURNING *;
    `;

    const values = [
      nombre,
      apellido_paterno,
      apellido_materno,
      correo,
      celular,
      categoria,
      grado_instruccion,
      area,
      rol,
      carrera,
      cvFile ? await readFileAsync(cvFile) : null,
      voluntarioId,
    ];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado.' });
    }

    res.status(200).json({ message: 'Voluntario actualizado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar voluntario:', error);
    res.status(500).json({ message: 'Error en el servidor al actualizar el voluntario.' });
  }
});

// Ruta para actualizar voluntarios
app.put('/voluntarios/:id', async (req, res) => {
  const { id } = req.params;
  const fields = req.body; // Datos enviados en el cuerpo
  const cvFile = req.file ? req.file.path : null; // Ruta del archivo si se envía

  try {
    // Verificar si el voluntario existe
    const query = `SELECT * FROM voluntarios WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }

    // Construir la consulta de actualización dinámicamente
    const setFields = Object.keys(fields)
      .map((key, index) => `${key} = $${index + 1}`)
      .join(', ');
    const values = Object.values(fields);

    if (cvFile) {
      setFields += `, cv = $${values.length + 1}`;
      values.push(await readFileAsync(cvFile));
    }

    const updateQuery = `UPDATE voluntarios SET ${setFields} WHERE id = $${values.length + 1}`;
    await pool.query(updateQuery, [...values, id]);

    res.json({ message: 'Voluntario actualizado correctamente' });
  } catch (error) {
    console.error('Error al actualizar voluntario:', error);
    res.status(500).json({ message: 'Error al actualizar voluntario' });
  }
});

app.put('/voluntarios/:id/estado', async (req, res) => {
  const voluntarioId = req.params.id;
  const { nuevoEstado } = req.body;



  try {
    const result = await pool.query(
      'UPDATE voluntarios SET estado_voluntario = $1 WHERE id = $2 RETURNING *',
      [nuevoEstado === 'Activo', voluntarioId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }

    res.json({ message: 'Estado del voluntario actualizado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al cambiar el estado del voluntario:', error);
    res.status(500).json({ message: 'Error en el servidor al cambiar el estado del voluntario' });
  }
});


//RUTA PARA ACTUALIZAR VOLUNTARIO DESDE SU PROPIA VISTA

app.get('/voluntarios/unico/:id', authenticateToken, async (req, res) => {
  const voluntarioId = req.params.id;

  // console.log(`ID recibido: ${voluntarioId}`); // Log para depuración

  try {
    const query = `
      SELECT
        id, dni, nombre, apellido_paterno, apellido_materno, correo,
        ciudad_residencia, celular, grado_instruccion, instagram, facebook, linkedin,
        fecha_ingreso, fecha_nacimiento, categoria, area, rol, carrera
      FROM voluntarios
      WHERE id = $1
    `;
    const result = await pool.query(query, [voluntarioId]);

    // console.log('Resultados de la consulta:', result.rows); // Log para depuración

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado.' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener información del voluntario:', error);
    res.status(500).json({ message: 'Error al obtener información del voluntario.' });
  }
});


app.put('/voluntarios/unico/:id', authenticateToken, async (req, res) => {
  const voluntarioId = req.params.id;
  const {
    ciudad_residencia,
    celular,
    grado_instruccion,
    instagram,
    facebook,
    linkedin,
  } = req.body;

  try {
    const query = `
      UPDATE voluntarios
      SET
        ciudad_residencia = $1,
        celular = $2,
        grado_instruccion = $3,
        instagram = $4,
        facebook = $5,
        linkedin = $6
      WHERE id = $7
      RETURNING *;
    `;
    const values = [
      ciudad_residencia,
      celular,
      grado_instruccion,
      instagram || null,
      facebook || null,
      linkedin || null,
      voluntarioId,
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado.' });
    }

    res.status(200).json({
      message: 'Información actualizada correctamente.',
      data: result.rows[0],
    });
  } catch (error) {
    console.error('Error al actualizar información del voluntario:', error);
    res.status(500).json({ message: 'Error al actualizar información del voluntario.' });
  }
});


// Endpoint para cambiar la contraseña de un usuario o voluntario
// app.put('/:tabla/:id/cambiar-contrasena', async (req, res) => {
//   const { tabla, id } = req.params; // La tabla puede ser "usuarios" o "voluntarios"
//   const { contrasenaActual, nuevaContrasena } = req.body;

//   if (!['usuarios', 'voluntarios'].includes(tabla)) {
//     return res.status(400).json({ message: 'Tabla no válida. Use usuarios o voluntarios.' });
//   }

//   try {
//     // Verificar si el registro existe
//     const query = `SELECT * FROM ${tabla} WHERE id = $1`;
//     const result = await pool.query(query, [id]);

//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: `${tabla.slice(0, -1)} no encontrado` });
//     }

//     const usuario = result.rows[0];

//     // Verificar la contraseña actual
//     const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
//     if (!contrasenaValida) {
//       return res.status(401).json({ message: 'Contraseña actual incorrecta' });
//     }

//     // Hashear la nueva contraseña
//     const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

//     // Actualizar la contraseña en la base de datos
//     const updateQuery = `UPDATE ${tabla} SET password = $1 WHERE id = $2`;
//     await pool.query(updateQuery, [nuevaContrasenaHash, id]);

//     res.json({ message: 'Contraseña actualizada correctamente' });
//   } catch (error) {
//     console.error(`Error al actualizar la contraseña del ${tabla.slice(0, -1)}:`, error);
//     res.status(500).json({ message: `Error al actualizar la contraseña del ${tabla.slice(0, -1)}` });
//   }
// });






app.get('/voluntarios', async (req, res) => {
  try {
      const result = await pool.query("select *from voluntarios'");
      res.json(result.rows);
  } catch (error) {
      console.error('Error al obtener voluntarios:', error);
      res.status(500).json({ message: 'Error en el servidor al obtener voluntarios' });
  }
});

// Obtener historial de voluntariados para un voluntario
app.get('/voluntarios/:id/historial', async (req, res) => {
  const { id } = req.params; // ID del voluntario

  try {
    const query = `
    (
      SELECT
        hv.id_voluntariado AS id_voluntariado,
        hv.nombre_voluntariado AS nombre_voluntariado,
        hv.lugar,
        NULL AS descripcion,
        hv.fecha_cierre,
        hv.estado,
        hv.logros
      FROM
        historial_voluntariados hv
      WHERE
        EXISTS (
          SELECT 1
          FROM jsonb_array_elements(hv.voluntarios::jsonb) obj
          WHERE (obj->>'id_voluntario')::int = $1
        )
    )
    UNION ALL
    (
      SELECT
        v.id AS id_voluntariado,
        v.nombre AS nombre_voluntariado,
        v.lugar,
        v.descripcion,
        NULL AS fecha_cierre,
        ev.estado,
        NULL AS logros
      FROM
        voluntariados v
      JOIN
        (
          SELECT DISTINCT ON (id_voluntariado) id_voluntariado, estado
          FROM estados_voluntariado
          ORDER BY id_voluntariado, fecha DESC
        ) ev
        ON ev.id_voluntariado = v.id
      JOIN
        voluntarios_asignados va ON v.id = va.id_voluntariado
      WHERE
        va.id_voluntario = $1
        AND ev.estado != 'Cerrado'
    )
    ORDER BY fecha_cierre DESC NULLS LAST;
    `;

    // Ejecutar la consulta
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontraron voluntariados para este voluntario' });
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener historial:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el historial' });
  }
});


app.get('/dashboard/estadisticas', authenticateToken, async (req, res) => {
  try {
    // Datos simulados (reemplaza estas consultas con las reales)
    const totalVoluntarios = await pool.query('SELECT COUNT(*) FROM voluntarios');
    const totalBeneficiarios = await pool.query('SELECT COUNT(*) FROM beneficiarios');
    const voluntariadosActivos = await pool.query("SELECT COUNT(*) FROM voluntariados WHERE estado_alta =true");
    const totalBenefactores = await pool.query('SELECT COUNT(*) FROM benefactores');

    res.status(200).json({
      voluntarios: totalVoluntarios.rows[0].count,
      beneficiarios: totalBeneficiarios.rows[0].count,
      voluntariados: voluntariadosActivos.rows[0].count,
      benefactores: totalBenefactores.rows[0].count,
    });
  } catch (error) {
    console.error('Error al obtener estadísticas:', error);
    res.status(500).json({ message: 'Error al obtener estadísticas del dashboard' });
  }
});


//obtener feefback voluntariado logueado vs voluntariados asignados

app.get('/voluntarios/feedback/:id_voluntario/:id_voluntariado', async (req, res) => {
  const { id_voluntario, id_voluntariado } = req.params;

  if (!id_voluntario || !id_voluntariado) {
    return res.status(400).json({ message: 'Faltan parámetros requeridos: id_voluntario o id_voluntariado.' });
  }

  // console.log('Parámetros recibidos:', id_voluntario, id_voluntariado);

  try {
    const query = `
      SELECT
        f.id,
        f.fecha,
        f.adicional,
        f.mentor,
        f.descripcion,
        f.tipo
      FROM
        feedback f
      WHERE
        f.id_voluntario = $1
        AND f.id_voluntariado = $2
      ORDER BY
        f.fecha DESC;
    `;

    const feedbacks = await pool.query(query, [id_voluntario, id_voluntariado]);

    // console.log('Resultados de la consulta:', feedbacks.rows);

    // Si no hay feedbacks, devolver un array vacío con código 200
    res.status(200).json({ feedbacks: feedbacks.rows });
  } catch (error) {
    console.error('Error al obtener los feedbacks:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener los feedbacks.' });
  }
});






//Obtener feedback de un voluntariado específico
// app.get('/voluntarios/:id/feedback', async (req, res) => {
//   const { id } = req.params; // ID del voluntario

//   try {
//     const query = `
//       SELECT
//         fb.id AS feedback_id,
//         fb.fecha AS feedback_fecha,
//         fb.descripcion,
//         fb.tipo,
//         fb.adicional,
//         fb.mentor,
//         v.id AS voluntariado_id,
//         v.nombre AS voluntariado_nombre
//       FROM feedback fb
//       JOIN voluntarios_asignados va ON fb.id_voluntario = va.id_voluntario
//       JOIN voluntariados v ON va.id_voluntariado = v.id
//       WHERE fb.id_voluntario = $1
//       ORDER BY fb.fecha;
//     `;

//     // Ejecuta la consulta SQL
//     const result = await pool.query(query, [id]);

//     // Si no se encuentran resultados
//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: 'No se encontró feedback para este voluntario' });
//     }

//     // Si se encuentran resultados, devolverlos
//     res.json(result.rows);
//   } catch (error) {
//     console.error('Error al obtener feedback:', error);
//     res.status(500).json({ message: 'Error en el servidor al obtener el feedback' });
//   }
// });

app.get('/voluntarios/:id/feedback', async (req, res) => {
  const { id } = req.params; // ID del voluntario

  try {
    const query = `
      SELECT
        fb.id AS feedback_id,
        fb.fecha AS feedback_fecha,
        fb.descripcion,
        fb.tipo,
        fb.adicional,
        fb.mentor,
        fb.id_voluntariado AS voluntariado_id,
        v.nombre AS voluntariado_nombre
      FROM
        feedback fb
      JOIN
        voluntariados v ON fb.id_voluntariado = v.id
      WHERE
        fb.id_voluntario = $1
      ORDER BY
        fb.fecha DESC;
    `;

    // Ejecuta la consulta SQL
    const result = await pool.query(query, [id]);

    // Si no se encuentran resultados
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontró feedback para este voluntario' });
    }

    // Si se encuentran resultados, devolverlos
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener feedback:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el feedback' });
  }
});


// *************SECCION VARIABLES DEL SISTEMA ****************

app.get('/variables-sistema', async (req, res) => {
  try {
      const result = await pool.query('SELECT * FROM variables');
      res.json(result.rows);
  } catch (error) {
      console.error('Error al obtener usuarios:', error);
      res.status(500).json({ message: 'Error en el servidor al obtener usuarios' });
  }
});

app.get('/variables-sistema/valores', async (req, res) => {
  const nombreVariable = req.query.nombre; // Obtiene el nombre de la variable de los parámetros de la consulta

  if (!nombreVariable) {
    return res.status(400).json({ message: 'El nombre de la variable es requerido' });
  }

  try {
      const result = await pool.query(`
        SELECT valor
        FROM (
          SELECT UNNEST(ARRAY[valor1, valor2, valor3]) AS valor
          FROM public.variables
          WHERE Nombre = $1
        ) AS valores
        WHERE valor <> ''
        ORDER BY valor ASC;
      `, [nombreVariable]);
      res.json(result.rows.map(row => row.valor));
  } catch (error) {
      console.error(`Error al obtener los valores para la variable ${nombreVariable}:`, error);
      res.status(500).json({ message: 'Error en el servidor al obtener los valores' });
  }
});

app.post('/variables-sistema/registro', async (req, res) => {
  const { nombre,descripcion, valor1, valor2, valor3 } = req.body;

  try {
    // Validar campos
    if (!nombre) {
      return res.status(400).json({ message: 'El nombre es obligatorio' });
    }

    if (!valor1) {
      return res.status(400).json({ message: 'El Valor1 es obligatorio' });
    }

    // Insertar la variable a la Bd
    const insertQuery = await pool.query(
      'INSERT INTO variables (nombre, descripcion, valor1, valor2,valor3,estado) VALUES ($1, $2, $3, $4, $5, $6)',
      [nombre, descripcion, valor1,valor2,valor3, true]
    );
    res.json({ message: 'Registrado correctamente', modal: 'Registrado' });
  } catch (error) {
    console.error('Error en el registro de la variable:', error);
    res.status(500).json({ message: 'No es posible realizar el registro' });
  }
});
app.put('/variables-sistema/:id/estado', async (req, res) => {
  const variableId = req.params.id;
  const { nuevoEstado } = req.body; // Nuevo estado del usuario (baja o alta)

  try {
    // Verificar si el usuario existe en la base de datos
    const userQuery = await pool.query('SELECT * FROM variables WHERE id = $1', [variableId]);
    const variable = userQuery.rows[0];

    if (!variable) {
      return res.status(404).json({ message: 'variable no encontrada' });
    }

    let estadoVariable;
    // Determinar el nuevo estado del usuario
    if (nuevoEstado === 'alta') {
      estado = true;
    } else if (nuevoEstado === 'baja') {
      estado = false;
    } else {
      return res.status(400).json({ message: 'El nuevo estado debe ser "alta" o "baja"' });
    }

    // Actualizar el estado del usuario
    await pool.query('UPDATE variables SET estado = $1 WHERE id = $2', [estado, variableId]);

    // Enviar respuesta exitosae
    res.json({ message: `La variable ha sido marcada como "${nuevoEstado}"` });
  } catch (error) {
    console.error('Error al cambiar el estado de la variable :', error);
    res.status(500).json({ message: 'No es posible cambiar el estado de la variable' });
  }
});
app.get('/variables-sistema/:id', async (req, res) => {
  const { id } = req.params; // Extrae el ID del parámetro de ruta

  try {
    // Realiza una consulta a la base de datos para obtener el usuario por su ID
    const result = await pool.query('SELECT * FROM variables WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      // Si no se encuentra el usuario, devuelve un error 404
      return res.status(404).json({ message: 'Variable no encontrada' });
    }

    // Si el usuario se encuentra, devuelve el usuario como respuesta JSON
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener Variable por ID:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener La variable' });
  }
});
app.put('/variables-sistema/:id', async (req, res) => {
  const variableId = req.params.id;
  const { nombre, descripcion, valor1, valor2,valor3 } = req.body;

  try {
    // Verificar si el usuario existe en la base de datos
    const userQuery = await pool.query('SELECT * FROM variables WHERE id = $1', [variableId]);
    const variable = userQuery.rows[0];

    if (!variable) {
      return res.status(404).json({ message: 'Variable no encontrada' });
    }

    // Actualizar la información del usuario
    await pool.query(
      'UPDATE variables SET nombre = $1, descripcion = $2, valor1 = $3, valor2 = $4 , valor3=$5 WHERE id = $6',
      [nombre, descripcion, valor1, valor2,valor3 ,variableId]
    );

    res.json({ message: 'Variable actualizada correctamente' });
  } catch (error) {
    console.error('Error al editar Variable:', error);
    res.status(500).json({ message: 'Error al editar Variable' });
  }
});


// *************SECCION VOLUTARIADOS****************

// function authenticateToken(req, res, next) {
//   const token = req.get('Authorization')?.split(' ')[1];
//   // const token = authHeader ? authHeader.split(' ')[1] : undefined;

//   if (!token) {
//     console.warn('Token no proporcionado');
//     return res.status(401).json({ message: 'Token no proporcionado' });
//   }

//   jwt.verify(token, process.env.JWT_SECRET || 'process.env.JWT_SECRET', (err, user) => {
//     if (err) {
//       console.error('Error de verificación de token:', err);
//       return res.status(403).json({ message: 'Token no válido' });
//     }



//     if (!user || !user.id || !user.tipo_usuario) {
//       console.warn('Información incompleta en el token:', user);
//       return res.status(403).json({ message: 'El token no contiene información completa del usuario' });
//     }

//     req.user = user; // Almacenar el usuario decodificado
//     next();
//   });
// }
function authenticateToken(req, res, next) {
  // Obtiene el header Authorization
  const authHeader = req.get('Authorization');
  const token = authHeader?.split(' ')[1]; // Extrae el token después de "Bearer"
console.log(token);
  // Si no hay token, responde con un error
  if (!token) {
    console.warn('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  // Verifica el token
  const jwtSecret = process.env.JWT_SECRET || 'default_secret';
  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error('Error de verificación de token:', err.message);
      return res.status(403).json({ message: 'Token no válido o expirado' });
    }

    // Valida que el token decodificado contiene la información requerida
    if (!user || !user.id || !user.tipo_usuario) {
      console.warn('Información incompleta en el token:', user);
      return res.status(403).json({ message: 'El token no contiene información completa del usuario' });
    }

    // Almacena el usuario decodificado en req.user para su uso posterior
    req.user = user;
    next();
  });
}


module.exports = authenticateToken;

app.get('/voluntariados', authenticateToken, async (req, res) => {
  const rol  = req.user.tipo_usuario; // Asegúrate de que req.user esté correctamente poblado

  try {
    // Verifica que el rol esté presente y sea uno de los roles permitidos
    if (!rol || !['ADMINISTRADOR', 'RRHH', 'MENTOR'].includes(rol.toUpperCase())) {
      return res.status(403).json({ message: 'Acceso Restringido' });
    }

    const query = `
      SELECT
          v.id,
          v.nombre,
          v.tipo,
          v.fecha_inicio,
          v.estado_alta
      FROM voluntariados v
      ORDER BY v.fecha_inicio DESC;
    `;

    const result = await pool.query(query); // Ejecuta la consulta

    // Si no hay resultados, puedes manejarlo de manera adecuada
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontraron voluntariados' });
    }

    res.json(result.rows); // Responde con los datos
  } catch (error) {
    console.error('Error al obtener voluntariados:', error); // Registra el error en consola
    res.status(500).json({ message: 'Error en el servidor al obtener los voluntariados', error: error.message });
  }
});

app.get('/voluntariados/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
      const voluntariadoQuery = `SELECT * FROM voluntariados WHERE id = $1`;
      const estadoQuery = `
          SELECT estado FROM estados_voluntariado
          WHERE id_voluntariado = $1
          ORDER BY fecha DESC
          LIMIT 1;
      `;

      const voluntariadoResult = await pool.query(voluntariadoQuery, [id]);
      const estadoResult = await pool.query(estadoQuery, [id]);

      if (voluntariadoResult.rowCount === 0) {
          return res.status(404).json({ message: 'Voluntariado no encontrado' });
      }

      const voluntariado = voluntariadoResult.rows[0];
       voluntariado.estado_dinamico = estadoResult.rows[0]?.estado || 'Desconocido';

      // const estadoRow = estadoResult.rows[0];
      // voluntariado.estado_dinamico = estadoRow && estadoRow.estado ? estadoRow.estado : 'Desconocido';

      res.json(voluntariado);
  } catch (error) {
      console.error('Error al obtener voluntariado:', error);
      res.status(500).json({ message: 'Error en el servidor' });
  }
});


app.patch('/voluntariados/:id/estado-alta', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { estado_alta } = req.body; // true para De Alta, false para De Baja

  if (typeof estado_alta !== 'boolean') {
      return res.status(400).json({ message: 'El valor de estado_alta debe ser booleano (true o false).' });
  }

  try {
      const query = `
          UPDATE voluntariados
          SET estado_alta = $1
          WHERE id = $2
          RETURNING *;
      `;
      const result = await pool.query(query, [estado_alta, id]);

      if (result.rowCount === 0) {
          return res.status(404).json({ message: 'Voluntariado no encontrado.' });
      }

      res.status(200).json({ message: `Estado cambiado a ${estado_alta ? 'De Alta' : 'De Baja'}` });
  } catch (error) {
      console.error('Error al cambiar estado_alta:', error);
      res.status(500).json({ message: 'Error en el servidor al cambiar estado.' });
  }
});

app.post('/voluntariados/:id/aprobar', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
      // Verificar si el voluntariado existe
      const voluntariado = await pool.query(`SELECT * FROM voluntariados WHERE id = $1`, [id]);
      if (voluntariado.rowCount === 0) {
          return res.status(404).json({ message: 'Voluntariado no encontrado' });
      }

      // Insertar el nuevo estado 'Aprobado' en la tabla `estados_voluntariado`
      await pool.query(
          `INSERT INTO estados_voluntariado (id_voluntariado, estado) VALUES ($1, 'Aprobado')`,
          [id]
      );

      res.status(200).json({ message: 'Voluntariado aprobado con éxito.' });
  } catch (error) {
      console.error('Error al aprobar voluntariado:', error);
      res.status(500).json({ message: 'Error en el servidor al aprobar voluntariado' });
  }
});

// app.post('/voluntariados/:id/cerrar', authenticateToken, async (req, res) => {
//   const { id } = req.params;
//   const { presupuestoEjecutado, logros } = req.body;

//   try {
//     // Verificar si el voluntariado existe
//     const voluntariado = await pool.query(`SELECT * FROM voluntariados WHERE id = $1`, [id]);
//     if (voluntariado.rowCount === 0) {
//       return res.status(404).json({ message: 'Voluntariado no encontrado' });
//     }

//     // Validar los datos recibidos
//     if (!presupuestoEjecutado || isNaN(presupuestoEjecutado)) {
//       return res.status(400).json({ message: 'El presupuesto ejecutado es obligatorio y debe ser un número válido.' });
//     }

//     if (!logros || logros.length > 1000) {
//       return res.status(400).json({ message: 'Los logros son obligatorios y no deben superar los 1000 caracteres.' });
//     }

//     // Insertar el nuevo estado 'Cerrado' en la tabla `estados_voluntariado`
//     await pool.query(
//       `INSERT INTO estados_voluntariado (id_voluntariado, estado) VALUES ($1, 'Cerrado')`,
//       [id]
//     );

//     // Actualizar los datos adicionales del voluntariado (si hay una columna para esto)
//     await pool.query(
//       `UPDATE voluntariados SET presupuesto_ejecutado = $1, logros = $2 WHERE id = $3`,
//       [presupuestoEjecutado, logros, id]
//     );

//     res.status(200).json({ message: 'Voluntariado cerrado con éxito.' });
//   } catch (error) {
//     console.error('Error al cerrar voluntariado:', error);
//     res.status(500).json({ message: 'Error en el servidor al cerrar voluntariado.' });
//   }
// });

app.post('/voluntariados/:id/cerrar', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { presupuestoEjecutado, logros } = req.body;

  try {
    // Verificar si el voluntariado existe
    const voluntariado = await pool.query(`SELECT * FROM voluntariados WHERE id = $1`, [id]);
    if (voluntariado.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }

    // Validar los datos recibidos
    if (!presupuestoEjecutado || isNaN(presupuestoEjecutado)) {
      return res.status(400).json({ message: 'El presupuesto ejecutado es obligatorio y debe ser un número válido.' });
    }

    if (!logros || logros.length > 1000) {
      return res.status(400).json({ message: 'Los logros son obligatorios y no deben superar los 1000 caracteres.' });
    }

    // Insertar el estado "Cerrado" en la tabla estados_voluntariado
    await pool.query(
      `INSERT INTO estados_voluntariado (id_voluntariado, estado) VALUES ($1, 'Cerrado')`,
      [id]
    );

    // Registrar el historial
    const voluntarios = await pool.query(`SELECT * FROM voluntarios_asignados WHERE id_voluntariado = $1`, [id]);
    const evidencias = await pool.query(`SELECT * FROM evidencias WHERE voluntariado_id= $1`, [id]);
    const asistencias = await pool.query(`SELECT * FROM asistencias WHERE id_voluntariado = $1`, [id]);

    await pool.query(
      `INSERT INTO historial_voluntariados (
         id_voluntariado, nombre_voluntariado, tipo, estado, logros, presupuesto_ejecutado, fecha_cierre, voluntarios, evidencias, asistencias
       ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9)`,
      [
        voluntariado.rows[0].id,
        voluntariado.rows[0].nombre,
        voluntariado.rows[0].tipo,
        'Cerrado',
        logros,
        presupuestoEjecutado,
        JSON.stringify(voluntarios.rows),
        JSON.stringify(evidencias.rows),
        JSON.stringify(asistencias.rows)
      ]
    );

    // Liberar a los voluntarios asignados
    await pool.query(`DELETE FROM voluntarios_asignados WHERE id_voluntariado = $1`, [id]);

    res.status(200).json({ message: 'Voluntariado cerrado con éxito.' });
  } catch (error) {
    console.error('Error al cerrar voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor al cerrar voluntariado.' });
  }
});


app.get('/voluntariados/:id/historial', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Verificar si el historial del voluntariado existe
    const historial = await pool.query(
      `SELECT
        hv.id_voluntariado,
        hv.nombre,
        hv.tipo,
        hv.presupuesto_ejecutado,
        hv.logros,
        hv.fecha_cierre
       FROM historial_voluntariados hv
       WHERE hv.id_voluntariado = $1`,
      [id]
    );

    if (historial.rowCount === 0) {
      return res.status(404).json({ message: 'No se encontró historial para este voluntariado.' });
    }

    res.status(200).json(historial.rows[0]); // Devuelve un único registro (historial del voluntariado)
  } catch (error) {
    console.error('Error al obtener el historial del voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el historial del voluntariado.' });
  }
});


app.post('/voluntariados', authenticateToken, async (req, res) => {
  const {
      nombre, tipo, fecha_inicio, fecha_fin, objetivoGeneral,
      objetivoEspecifico1, objetivoEspecifico2, objetivoEspecifico3,
      objetivoEspecifico4, objetivoEspecifico5, publicoObjetivo,
      beneficiariosDirectos, beneficiariosIndirectos, presupuestoInicial,
      aliados
  } = req.body;

  const id_usuario = req.user.id;

  if (!id_usuario) {
      return res.status(401).json({ message: 'El usuario no está autenticado.' });
  }

  if (!nombre || !tipo || !fecha_inicio || !fecha_fin || !objetivoGeneral || !publicoObjetivo) {
      return res.status(400).json({ message: 'Faltan datos obligatorios' });
  }

  try {
      // Insertar en la tabla voluntariados con estado_alta como FALSE por defecto
      const query = `
          INSERT INTO voluntariados (
              nombre, tipo, fecha_inicio, fecha_cierre_proyectada, objetivo_general,
              objetivo_especifico1, objetivo_especifico2, objetivo_especifico3,
              objetivo_especifico4, objetivo_especifico5, publico_objetivo,
              beneficiarios_directos, beneficiarios_indirectos, presupuesto_inicial, aliados, id_usuario, estado_alta
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
          RETURNING id;
      `;

      const values = [
          nombre, tipo, fecha_inicio, fecha_fin, objetivoGeneral,
          objetivoEspecifico1 || null, objetivoEspecifico2 || null, objetivoEspecifico3 || null,
          objetivoEspecifico4 || null, objetivoEspecifico5 || null, publicoObjetivo,
          beneficiariosDirectos || null, beneficiariosIndirectos || null,
          presupuestoInicial || null, aliados || null, id_usuario, false // estado_alta por defecto
      ];

      const result = await pool.query(query, values);
      const idVoluntariado = result.rows[0].id;

      // Insertar el estado inicial 'Pendiente' en estados_voluntariado
      await pool.query(
          `INSERT INTO estados_voluntariado (id_voluntariado, estado) VALUES ($1, 'Pendiente')`,
          [idVoluntariado]
      );

      res.status(201).json({ message: 'Voluntariado creado con estado inicial Pendiente y De Baja', id: idVoluntariado });
  } catch (error) {
      console.error('Error al crear voluntariado:', error);
      res.status(500).json({ message: 'Error en el servidor al crear voluntariado' });
  }
});

app.patch('/voluntariados/:id/estado-alta', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { estado_alta } = req.body; // true para De Alta, false para De Baja

  if (typeof estado_alta !== 'boolean') {
      return res.status(400).json({ message: 'El valor de estado_alta debe ser booleano (true o false).' });
  }

  try {
      const query = `
          UPDATE voluntariados
          SET estado_alta = $1
          WHERE id = $2
          RETURNING *;
      `;
      const result = await pool.query(query, [estado_alta, id]);

      if (result.rowCount === 0) {
          return res.status(404).json({ message: 'Voluntariado no encontrado.' });
      }

      res.status(200).json({ message: `Estado cambiado a ${estado_alta ? 'De Alta' : 'De Baja'}` });
  } catch (error) {
      console.error('Error al cambiar estado_alta:', error);
      res.status(500).json({ message: 'Error en el servidor al cambiar estado.' });
  }
});





app.put('/voluntariados/:id/aprobar', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `UPDATE voluntariados SET estado_voluntariado = 'Aprobado' WHERE id = $1`;
    await pool.query(query, [id]);
    res.status(200).json({ message: 'Voluntariado aprobado exitosamente.' });
  } catch (error) {
    console.error('Error al aprobar el voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.put('/voluntariados/:id/estado', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { estado } = req.body; // 'De Alta' o 'De Baja'
  try {
    const query = `UPDATE voluntariados SET estado_voluntariado = $1 WHERE id = $2`;
    await pool.query(query, [estado, id]);
    res.status(200).json({ message: `Voluntariado cambiado a estado ${estado}` });
  } catch (error) {
    console.error('Error al cambiar estado:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.put('/voluntariados/:id/cerrar', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { presupuesto, logros } = req.body;
  if (!presupuesto || !logros.trim()) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }
  try {
    const query = `
      UPDATE voluntariados
      SET estado_voluntariado = 'Cerrado', presupuesto_ejecutado = $1, logros = $2
      WHERE id = $3
    `;
    await pool.query(query, [presupuesto, logros, id]);
    res.status(200).json({ message: 'Voluntariado cerrado exitosamente.' });
  } catch (error) {
    console.error('Error al cerrar el voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});



/****************EVIDENCIAS FLUJO VOLUNTARIADO************* */
app.get('/voluntariados/:id/evidencias', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT id, fecha_evidencia, descripcion
      FROM evidencias
      WHERE voluntariado_id = $1
    `;
    const result = await pool.query(query, [id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener evidencias:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/evidencias/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT id, fecha_evidencia, descripcion, incidentes, asistencia_mentores,asistencia_voluntarios ,porcentaje_participacion
      FROM evidencias
      WHERE id = $1
    `;
    const result = await pool.query(query, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Evidencia no encontrada' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener la evidencia:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/voluntariados/:id/evidencias', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    fecha_evidencia,
    descripcion,
    incidentes,
    asistencia_mentores,
    porcentaje_participacion,
    asistencia_voluntarios,
  } = req.body;

  try {
    const query = `
      INSERT INTO evidencias (
        voluntariado_id, fecha_evidencia, descripcion, incidentes,
        asistencia_mentores,asistencia_voluntarios ,porcentaje_participacion
      )
      VALUES ($1, $2, $3, $4, $5, $6,$7)
      RETURNING *;
    `;
    const values = [
      id,
      fecha_evidencia,
      descripcion,
      incidentes,
      asistencia_mentores,
      asistencia_voluntarios,
      porcentaje_participacion
    ];

    const result = await pool.query(query, values);
    res.status(201).json({ message: 'Evidencia registrada correctamente.', evidencia: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar evidencia:', error);
    res.status(500).json({ message: 'Error al registrar la evidencia.' });
  }
});

app.get('/voluntariados/:id/evidencias/calculos', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Obtener la cantidad total de voluntarios asignados al voluntariado
    const totalVoluntariosQuery = `
      SELECT COUNT(*) AS total_voluntarios
      FROM voluntarios_asignados
      WHERE id_voluntariado = $1
    `;
    const totalVoluntariosResult = await pool.query(totalVoluntariosQuery, [id]);
    const totalVoluntarios = parseInt(totalVoluntariosResult.rows[0].total_voluntarios, 10) || 0;

    // Calcular la cantidad de asistentes (estado = 'Presente')
    const asistenciaQuery = `
      SELECT COUNT(*) AS asistentes_voluntarios
      FROM estado_asistencia ea
      INNER JOIN asistencias a ON ea.asistencia_id = a.id
      WHERE a.id_voluntariado = $1 AND ea.estado = 'Presente'
    `;
    const asistenciaResult = await pool.query(asistenciaQuery, [id]);
    const asistentesVoluntarios = parseInt(asistenciaResult.rows[0].asistentes_voluntarios, 10) || 0;

    // Calcular el porcentaje de participación
    const porcentajeParticipacion = totalVoluntarios > 0
      ? (asistentesVoluntarios / totalVoluntarios) * 100
      : 0;

    res.status(200).json({
      porcentajeParticipacion: porcentajeParticipacion.toFixed(2),
      asistenciaVoluntarios: asistentesVoluntarios,
    });
  } catch (error) {
    console.error('Error al calcular valores:', error);
    res.status(500).json({ message: 'Error al calcular valores' });
  }
});


app.delete('/voluntariados/evidencias/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const deleteQuery = `
      DELETE FROM evidencias
      WHERE id = $1
    `;
    const result = await pool.query(deleteQuery, [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Evidencia no encontrada.' });
    }

    res.status(200).json({ message: 'Evidencia eliminada correctamente.' });
  } catch (error) {
    console.error('Error al eliminar la evidencia:', error);
    res.status(500).json({ message: 'Error al eliminar la evidencia.' });
  }
});

///////// ASISTENCIAS /////////////////////


app.get('/voluntariados/:id/asistencias', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
      SELECT
        a.id,
        a.id_voluntariado,
        a.fecha_asistencia,
        a.nombre_sesion,
        COUNT(ea.estado) AS total_asistentes
      FROM asistencias a
      LEFT JOIN estado_asistencia ea
      ON a.id = ea.asistencia_id AND ea.estado = 'Presente'
      WHERE a.id_voluntariado = $1
      GROUP BY a.id;
    `;
    const result = await pool.query(query, [id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener asistencias:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});


app.post('/voluntariados/:id/asistencias', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { fecha_asistencia, nombre_sesion, estados } = req.body;

  try {
    // Insertar la sesión de asistencia
    const asistenciaQuery = `
      INSERT INTO asistencias (id_voluntariado, fecha_asistencia, nombre_sesion)
      VALUES ($1, $2, $3)
      RETURNING id;
    `;
    const asistenciaResult = await pool.query(asistenciaQuery, [id, fecha_asistencia, nombre_sesion]);
    const asistenciaId = asistenciaResult.rows[0].id;

    // Insertar los estados de los voluntarios
    const estadoQuery = `
      INSERT INTO estado_asistencia (asistencia_id, voluntario_id, estado)
      VALUES ($1, $2, $3);
    `;
    for (const estado of estados) {
      await pool.query(estadoQuery, [asistenciaId, estado.voluntario_id, estado.estado]);
    }

    res.status(201).json({ message: 'Asistencia registrada exitosamente' });
  } catch (error) {
    console.error('Error al registrar asistencia:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/voluntariados/asistencias/:id/detalle', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Obtener los detalles de la asistencia
    const asistenciaQuery = `
      SELECT id, fecha_asistencia, nombre_sesion
      FROM asistencias
      WHERE id = $1
    `;
    const asistenciaResult = await pool.query(asistenciaQuery, [id]);
    const asistencia = asistenciaResult.rows[0];

    if (!asistencia) {
      return res.status(404).json({ message: 'Asistencia no encontrada' });
    }

    // Obtener los voluntarios y sus estados, incluyendo el voluntario_id
    const voluntariosQuery = `
      SELECT v.id AS voluntario_id, v.nombre, ea.estado
      FROM estado_asistencia ea
      INNER JOIN voluntarios v ON ea.voluntario_id = v.id
      WHERE ea.asistencia_id = $1
    `;
    const voluntariosResult = await pool.query(voluntariosQuery, [id]);

    res.status(200).json({
      asistencia,
      voluntarios: voluntariosResult.rows,
    });
  } catch (error) {
    console.error('Error al obtener los detalles de la asistencia:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});


app.put('/voluntariados/asistencias/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { fecha, nombreSesion, estados } = req.body;

  try {
    // Actualizar datos de la asistencia
    const updateAsistenciaQuery = `
      UPDATE asistencias
      SET fecha_asistencia = $1, nombre_sesion = $2
      WHERE id = $3
    `;
    await pool.query(updateAsistenciaQuery, [fecha, nombreSesion, id]);

    // Actualizar estados de los voluntarios
    const deleteEstadosQuery = `DELETE FROM estado_asistencia WHERE asistencia_id = $1`;
    await pool.query(deleteEstadosQuery, [id]);

    const insertEstadoQuery = `
      INSERT INTO estado_asistencia (asistencia_id, voluntario_id, estado)
      VALUES ($1, $2, $3)
    `;
    for (const estado of estados) {
      await pool.query(insertEstadoQuery, [id, estado.voluntario_id, estado.estado]);
    }

    res.status(200).json({ message: 'Asistencia actualizada exitosamente' });
  } catch (error) {
    console.error('Error al actualizar asistencia:', error);
    res.status(500).json({ message: 'Error al actualizar asistencia' });
  }
});







app.get('/voluntariados/:id/voluntarios', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT
        v.id,
        v.dni,
        v.nombre,
        v.apellido_paterno,
        v.apellido_materno,
        v.correo,
        v.celular,
        v.ciudad_residencia,
        v.rol,
        v.area,
        v.categoria,
        v.grado_instruccion,
        v.carrera
      FROM voluntarios v
      INNER JOIN voluntarios_asignados va ON va.id_voluntario = v.id
      WHERE va.id_voluntariado = $1
    `;
    const result = await pool.query(query, [id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener voluntarios asignados:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});



// Actualizar un voluntariado
app.put('/voluntariados/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;


  const {
    nombre, // Incluye el nombre en la destructuración
    tipo,
    fecha_inicio,
    fecha_fin,
    objetivoGeneral,
    objetivoEspecifico1,
    objetivoEspecifico2,
    objetivoEspecifico3,
    objetivoEspecifico4,
    objetivoEspecifico5,
    publicoObjetivo,
    beneficiariosDirectos,
    beneficiariosIndirectos,
    presupuestoInicial,
    aliados,
  } = req.body;

  try {
    if (!nombre || !tipo || !fecha_inicio || !fecha_fin || !objetivoGeneral || !publicoObjetivo) {
      return res.status(400).json({ message: 'Campos obligatorios faltantes' });
    }

    const query = `
      UPDATE voluntariados
      SET nombre = $1, -- Agregamos el campo 'nombre' a la consulta
          tipo = $2,
          fecha_inicio = $3,
          fecha_cierre_proyectada = $4,
          objetivo_general = $5,
          objetivo_especifico1 = $6,
          objetivo_especifico2 = $7,
          objetivo_especifico3 = $8,
          objetivo_especifico4 = $9,
          objetivo_especifico5 = $10,
          publico_objetivo = $11,
          beneficiarios_directos = $12,
          beneficiarios_indirectos = $13,
          presupuesto_inicial = $14,
          aliados = $15
      WHERE id = $16
      RETURNING *;
    `;

    const values = [
      nombre, // Añadimos el valor del nombre aquí
      tipo,
      fecha_inicio,
      fecha_fin,
      objetivoGeneral,
      objetivoEspecifico1 || null,
      objetivoEspecifico2 || null,
      objetivoEspecifico3 || null,
      objetivoEspecifico4 || null,
      objetivoEspecifico5 || null,
      publicoObjetivo,
      beneficiariosDirectos || null,
      beneficiariosIndirectos || null,
      presupuestoInicial || null,
      aliados || null,
      id,
    ];



    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }



    res.status(200).json({ message: 'Voluntariado actualizado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar voluntariado:', error);
    res.status(500).json({ message: 'Error del servidor', error: error.message });
  }
});
// Endpoint para cambiar el estado de un voluntariado
app.put('/voluntariados/:id/estado', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { estado_voluntariado } = req.body; // Usar el nuevo nombre de columna

  if (!estado_voluntariado) {
    return res.status(400).json({ message: 'Campo estado_voluntariado es obligatorio' });
  }

  try {
    const query = `
      UPDATE voluntariados
      SET estado_voluntariado = $1
      WHERE id = $2
      RETURNING *;
    `;
    const values = [estado_voluntariado, id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }

    res.status(200).json({ message: 'Estado actualizado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar estado del voluntariado:', error);
    res.status(500).json({ message: 'Error del servidor', error: error.message });
  }
});

// Endpoint para cambiar el estado de un voluntariado
app.put('/voluntariados/:id/estado', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { estado_voluntariado } = req.body; // Usar el nuevo nombre de columna

  if (!estado_voluntariado) {
    return res.status(400).json({ message: 'Campo estado_voluntariado es obligatorio' });
  }

  try {
    const query = `
      UPDATE voluntariados
      SET estado_voluntariado = $1
      WHERE id = $2
      RETURNING *;
    `;
    const values = [estado_voluntariado, id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }

    res.status(200).json({ message: 'Estado actualizado correctamente', data: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar estado del voluntariado:', error);
    res.status(500).json({ message: 'Error del servidor', error: error.message });
  }
});

app.get('/voluntariados/voluntarios/no-asignados', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT v.id, CONCAT(v.nombre, ' ', v.apellido_paterno, ' ', v.apellido_materno) AS nombre_completo
      FROM voluntarios v
      LEFT JOIN voluntarios_asignados va ON v.id = va.id_voluntario
      WHERE va.id_voluntariado IS NULL;
    `;
    const result = await pool.query(query);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error al obtener voluntarios sin asignación:', error);
    res.status(500).json({ message: 'Error al obtener voluntarios sin asignación' });
  }
});

app.post('/voluntariados/voluntarios/asignar', authenticateToken, async (req, res) => {
  const { id_voluntariado, id_voluntario } = req.body;

  if (!id_voluntariado || !id_voluntario) {
    return res.status(400).json({ message: 'Faltan datos obligatorios' });
  }

  try {
    const query = `
      INSERT INTO voluntarios_asignados (id_voluntariado, id_voluntario)
      VALUES ($1, $2)
      RETURNING *;
    `;
    const values = [id_voluntariado, id_voluntario];
    const result = await pool.query(query, values);
    res.status(200).json({ message: 'Voluntario asignado con éxito', data: result.rows[0] });
  } catch (error) {
    console.error('Error al asignar voluntario:', error);
    res.status(500).json({ message: 'Error al asignar voluntario', error: error.message });
  }
});

// Obtener voluntarios asignados a un voluntariado
app.get('/voluntariados/:voluntariadoId/voluntarios', authenticateToken, async (req, res) => {
  const { voluntariadoId } = req.params;

  try {
    const query = `
      SELECT
        v.id AS id_voluntario,
        v.nombre,
        v.apellido_paterno,
        v.apellido_materno,
        va.fecha_asignacion
      FROM
        voluntarios_asignados va
      JOIN
        voluntarios v ON va.id_voluntario = v.id
      WHERE
        va.id_voluntariado = $1
    `;

    const result = await pool.query(query, [voluntariadoId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No hay voluntarios asignados para este voluntariado' });
    }

    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error al obtener voluntarios asignados:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener los voluntarios asignados' });
  }
});

// Desasignar un voluntario
app.delete('/voluntariados/:voluntariadoId/voluntarios/:voluntarioId', authenticateToken, async (req, res) => {
  const { voluntariadoId, voluntarioId } = req.params;

  try {
    const query = `
      DELETE FROM voluntarios_asignados
      WHERE id_voluntariado = $1 AND id_voluntario = $2
    `;
    const result = await pool.query(query, [voluntariadoId, voluntarioId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'No se encontró el registro para desasignar' });
    }

    res.status(200).json({ message: 'Voluntario desasignado con éxito' });
  } catch (error) {
    console.error('Error al desasignar voluntario:', error);
    res.status(500).json({ message: 'Error en el servidor al desasignar voluntario' });
  }
});









//******************* BENEFACTORES ************************** */


app.get('/benefactores', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT id, nombre, tipo, nombre_contacto, celular_contacto, direccion,
             razon_social, ruc, dni
      FROM benefactores
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al listar benefactores:', error);
    res.status(500).json({ message: 'Error al listar benefactores' });
  }
});

app.post('/benefactores', authenticateToken, async (req, res) => {
  const {
    nombre,
    tipo,
    nombre_contacto,
    celular_contacto,
    direccion,
    razon_social,
    ruc,
    dni,
  } = req.body;

  try {
    // Validar tipo de benefactor
    if (tipo === 'persona natural' && (!dni || razon_social || ruc)) {
      return res
        .status(400)
        .json({ message: 'Las personas naturales deben tener DNI y no RUC o razón social.' });
    }

    if (tipo === 'empresa' && (!razon_social || !ruc || dni)) {
      return res
        .status(400)
        .json({ message: 'Las empresas deben tener razón social, RUC y no DNI.' });
    }

    const query = `
      INSERT INTO benefactores (nombre, tipo, nombre_contacto, celular_contacto, direccion, razon_social, ruc, dni)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    const values = [
      nombre,
      tipo,
      nombre_contacto,
      celular_contacto,
      direccion,
      razon_social,
      ruc,
      dni,
    ];

    const result = await pool.query(query, values);
    res.status(201).json({ message: 'Benefactor registrado correctamente', benefactor: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar benefactor:', error);
    res.status(500).json({ message: 'Error al registrar benefactor' });
  }
});

app.get('/benefactores/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT id, nombre, tipo, nombre_contacto, celular_contacto, direccion, razon_social, ruc , dni
      FROM benefactores
      WHERE id = $1
    `;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Benefactor no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener benefactor:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});
app.put('/benefactores/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    nombre,
    tipo,
    nombre_contacto,
    celular_contacto,
    direccion,
    razon_social,
    ruc,
    dni,
  } = req.body;

  try {
    // Validar tipo de benefactor
    if (tipo === 'persona natural' && (!dni || razon_social || ruc)) {
      return res
        .status(400)
        .json({ message: 'Las personas naturales deben tener DNI y no RUC o razón social.' });
    }

    if (tipo === 'empresa' && (!razon_social || !ruc || dni)) {
      return res
        .status(400)
        .json({ message: 'Las empresas deben tener razón social, RUC y no DNI.' });
    }

    // Limpiar valores no aplicables
    const finalRuc = tipo === 'empresa' ? ruc : null;
    const finalRazonSocial = tipo === 'empresa' ? razon_social : null;
    const finalDni = tipo === 'persona natural' ? dni : null;

    const query = `
      UPDATE benefactores
      SET nombre = $1, tipo = $2, nombre_contacto = $3, celular_contacto = $4, direccion = $5,
          razon_social = $6, ruc = $7, dni = $8
      WHERE id = $9
      RETURNING *;
    `;
    const values = [
      nombre,
      tipo,
      nombre_contacto,
      celular_contacto,
      direccion,
      finalRazonSocial,
      finalRuc,
      finalDni,
      id,
    ];

    const result = await pool.query(query, values);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Benefactor no encontrado' });
    }

    res.json({ message: 'Benefactor actualizado correctamente', benefactor: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar benefactor:', error);
    res.status(500).json({ message: 'Error al actualizar benefactor' });
  }
});


app.delete('/benefactores/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = 'DELETE FROM benefactores WHERE id = $1 RETURNING *;';
    const result = await pool.query(query, [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Benefactor no encontrado' });
    }

    res.json({ message: 'Benefactor eliminado correctamente', benefactor: result.rows[0] });
  } catch (error) {
    console.error('Error al eliminar benefactor:', error);
    res.status(500).json({ message: 'Error al eliminar benefactor' });
  }
});




//******************* BENEFICIARIOS ************************** */

app.get('/beneficiarios', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT id, tipo, nombre, direccion, telefono, email, genero, edad, representante, ruc,dni ,comentarios, fecha_registro
      FROM beneficiarios
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al listar beneficiarios:', error);
    res.status(500).json({ message: 'Error al listar beneficiarios' });
  }
});

app.post('/beneficiarios', authenticateToken, async (req, res) => {

  const {
    tipo,
    nombre,
    direccion,
    telefono,
    email,
    genero,
    edad,
    representante,
    ruc,
    comentarios,
    dni,
  } = req.body;

  try {
    // Validaciones específicas según el tipo
    if (tipo === 'Persona' && (!nombre || !genero || !edad || !dni)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Persona" requieren nombre, género, edad y DNI.',
      });
    }

    if (tipo === 'Comunidad' && (!nombre || !representante)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Comunidad" requieren nombre y representante.',
      });
    }

    if (tipo === 'Organización' && (!nombre || !ruc)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Organización" requieren nombre y RUC.',
      });
    }

      const query = `
      INSERT INTO beneficiarios (tipo, nombre, direccion, telefono, email, genero, edad, representante, ruc, comentarios, dni)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *;
    `;
    const values = [tipo, nombre, direccion, telefono, email, genero, edad, representante, ruc, comentarios, dni];


    const result = await pool.query(query, values);
    res.status(201).json({
      message: 'Beneficiario registrado correctamente',
      beneficiario: result.rows[0],
    });
  } catch (error) {
    console.error('Error al registrar beneficiario:', error);
    res.status(500).json({ message: 'Error al registrar beneficiario' });
  }
});

app.get('/beneficiarios/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
      SELECT id, tipo, nombre, direccion, telefono, email, genero, edad, representante, ruc, comentarios, dni, fecha_registro
      FROM beneficiarios
      WHERE id = $1
    `;
    const values = [id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Beneficiario no encontrado' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener beneficiario:', error);
    res.status(500).json({ message: 'Error al obtener beneficiario' });
  }
});

app.put('/beneficiarios/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    tipo,
    nombre,
    direccion,
    telefono,
    email,
    genero,
    edad,
    representante,
    ruc,
    comentarios,
    dni,
  } = req.body;

  try {
    // Validaciones específicas según el tipo
    if (tipo === 'Persona' && (!nombre || !genero || !edad || !dni)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Persona" requieren nombre, género, edad y DNI.',
      });
    }


    if (tipo === 'Comunidad' && (!nombre || !representante)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Comunidad" requieren nombre y representante.',
      });
    }

    if (tipo === 'Organización' && (!nombre || !ruc)) {
      return res.status(400).json({
        message: 'Los beneficiarios tipo "Organización" requieren nombre y RUC.',
      });
    }

    const query = `
    UPDATE beneficiarios
    SET tipo = $1, nombre = $2, direccion = $3, telefono = $4, email = $5,
        genero = $6, edad = $7, representante = $8, ruc = $9, comentarios = $10, dni = $11
    WHERE id = $12
    RETURNING *;
  `;
  const values = [tipo, nombre, direccion, telefono, email, genero, edad, representante, ruc, comentarios, dni, id];


    const result = await pool.query(query, values);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Beneficiario no encontrado' });
    }

    res.status(200).json({
      message: 'Beneficiario actualizado correctamente',
      beneficiario: result.rows[0],
    });
  } catch (error) {
    console.error('Error al actualizar beneficiario:', error);
    res.status(500).json({ message: 'Error al actualizar beneficiario' });
  }
});






app.post('/voluntariados/:id/beneficiarios', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { id_beneficiario } = req.body;

  try {
    const query = `
      INSERT INTO voluntariados_beneficiarios (id_voluntariado, id_beneficiario)
      VALUES ($1, $2)
      RETURNING *;
    `;
    const values = [id, id_beneficiario];
    const result = await pool.query(query, values);
    res.status(201).json({ message: 'Beneficiario asignado correctamente', asignacion: result.rows[0] });
  } catch (error) {
    console.error('Error al asignar beneficiario:', error);
    res.status(500).json({ message: 'Error al asignar beneficiario' });
  }
});

app.post('/beneficiarios/:id/interacciones', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { id_voluntariado, tipo_interaccion, descripcion } = req.body;

  try {
    const query = `
      INSERT INTO interacciones_beneficiarios (id_beneficiario, id_voluntariado, tipo_interaccion, descripcion)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    const values = [id, id_voluntariado, tipo_interaccion, descripcion];
    const result = await pool.query(query, values);
    res.status(201).json({ message: 'Interacción registrada correctamente', interaccion: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar interacción:', error);
    res.status(500).json({ message: 'Error al registrar interacción' });
  }
});



//******************* feedback ************************** */

// app.post('/voluntarios/feedback', authenticateToken, async (req, res) => {
//   const { id_voluntario, fecha, adicional, mentor, descripcion, tipo } = req.body;

//   try {
//       if (!id_voluntario || !fecha || !mentor || !descripcion || !tipo) {
//           return res.status(400).json({ message: 'Todos los campos obligatorios deben ser completados.' });
//       }

//       const query = `
//           INSERT INTO feedback (id_voluntario, fecha, adicional, mentor, descripcion, tipo)
//           VALUES ($1, $2, $3, $4, $5, $6)
//           RETURNING *;
//       `;
//       const values = [id_voluntario, fecha, adicional || null, mentor, descripcion, tipo];

//       const result = await pool.query(query, values);
//       res.status(201).json({ message: 'Feedback registrado correctamente', feedback: result.rows[0] });
//   } catch (error) {
//       console.error('Error al registrar feedback:', error);
//       res.status(500).json({ message: 'Error al registrar feedback' });
//   }
// });
app.post('/voluntarios/feedback', authenticateToken, async (req, res) => {

  const { id_voluntario, id_voluntariado, fecha, adicional, mentor, descripcion, tipo } = req.body;

  try {
    // Validar que todos los campos obligatorios estén presentes
    if (!id_voluntario || !id_voluntariado || !fecha || !mentor || !descripcion || !tipo) {
      return res.status(400).json({ message: 'Todos los campos obligatorios deben ser completados.' });
    }

    // Verificar si el voluntariado existe
    const voluntariado = await pool.query(`SELECT * FROM voluntariados WHERE id = $1`, [id_voluntariado]);
    if (voluntariado.rowCount === 0) {
      return res.status(404).json({ message: 'El voluntariado especificado no existe.' });
    }

    // Verificar si el voluntario está asignado al voluntariado
    const asignacion = await pool.query(
      `SELECT * FROM voluntarios_asignados WHERE id_voluntario = $1 AND id_voluntariado = $2`,
      [id_voluntario, id_voluntariado]
    );
    if (asignacion.rowCount === 0) {
      return res.status(400).json({ message: 'El voluntario no está asignado a este voluntariado.' });
    }

    // Registrar el feedback
    const query = `
      INSERT INTO feedback (id_voluntario, id_voluntariado, fecha, adicional, mentor, descripcion, tipo)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;
    const values = [id_voluntario, id_voluntariado, fecha, adicional || null, mentor, descripcion, tipo];

    const result = await pool.query(query, values);

    // Responder con éxito
    res.status(201).json({ message: 'Feedback registrado correctamente', feedback: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar feedback:', error);
    res.status(500).json({ message: 'Error al registrar feedback' });
  }
});


app.get('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = 'SELECT * FROM feedback WHERE id = $1';
    const values = [id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Feedback no encontrado' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener feedback:', error);
    res.status(500).json({ message: 'Error al obtener feedback' });
  }
});

app.get('/voluntarios/feedback/:id_voluntario/:id_voluntariado', async (req, res) => {
  const { id_voluntario, id_voluntariado } = req.params;

  if (!id_voluntario || !id_voluntariado) {
    return res.status(400).json({ message: 'Faltan parámetros requeridos: id_voluntario o id_voluntariado.' });
  }

  // console.log('Parámetros recibidos:', id_voluntario, id_voluntariado);

  try {
    const query = `
      SELECT
        f.id,
        f.fecha,
        f.adicional,
        f.mentor,
        f.descripcion,
        f.tipo
      FROM
        feedback f
      WHERE
        f.id_voluntario = $1
        AND f.id_voluntariado = $2
      ORDER BY
        f.fecha DESC;
    `;

    const feedbacks = await pool.query(query, [id_voluntario, id_voluntariado]);

    // console.log('Resultados de la consulta:', feedbacks.rows);

    // Si no hay feedbacks, devolver un array vacío con código 200
    res.status(200).json({ feedbacks: feedbacks.rows });
  } catch (error) {
    console.error('Error al obtener los feedbacks:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener los feedbacks.' });
  }
});


app.get('/voluntarios/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM voluntarios WHERE id = $1",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener detalle del voluntario:', error);
    res.status(500).json({ message: 'Error al obtener detalle del voluntario' });
  }
});



app.put('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { fecha, adicional, mentor, descripcion, tipo } = req.body;



  try {
    if (!fecha || !mentor || !descripcion || !tipo) {
      return res.status(400).json({ message: 'Todos los campos obligatorios deben ser completados.' });
    }

    const query = `
      UPDATE feedback
      SET fecha = $1, adicional = $2, mentor = $3, descripcion = $4, tipo = $5
      WHERE id = $6
      RETURNING *;
    `;
    const values = [fecha, adicional || null, mentor, descripcion, tipo, id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Feedback no encontrado' });
    }

    res.status(200).json({ message: 'Feedback actualizado correctamente', feedback: result.rows[0] });
  } catch (error) {
    console.error('Error al editar feedback:', error);
    res.status(500).json({ message: 'Error al editar feedback' });
  }
});

// app.put('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
//   const { id } = req.params;
//   const { fecha, adicional, mentor, descripcion, tipo, id_voluntariado } = req.body;

//   try {
//     // Validar que todos los campos obligatorios estén presentes
//     if (!fecha || !mentor || !descripcion || !tipo || !id_voluntariado) {
//       return res.status(400).json({ message: 'Todos los campos obligatorios deben ser completados.' });
//     }

//     // Verificar si el `id_voluntariado` es válido
//     const voluntariadoQuery = `SELECT id FROM voluntariados WHERE id = $1`;
//     const voluntariadoResult = await pool.query(voluntariadoQuery, [id_voluntariado]);

//     if (voluntariadoResult.rowCount === 0) {
//       return res.status(404).json({ message: 'El voluntariado asociado no existe.' });
//     }

//     // Actualizar el feedback con los datos proporcionados
//     const query = `
//       UPDATE feedback
//       SET
//         fecha = $1,
//         adicional = $2,
//         mentor = $3,
//         descripcion = $4,
//         tipo = $5,
//         id_voluntariado = $6
//       WHERE id = $7
//       RETURNING *;
//     `;
//     const values = [fecha, adicional || null, mentor, descripcion, tipo, id_voluntariado, id];

//     const result = await pool.query(query, values);

//     if (result.rowCount === 0) {
//       return res.status(404).json({ message: 'Feedback no encontrado' });
//     }

//     res.status(200).json({ message: 'Feedback actualizado correctamente', feedback: result.rows[0] });
//   } catch (error) {
//     console.error('Error al editar feedback:', error);
//     res.status(500).json({ message: 'Error al editar feedback' });
//   }
// });


// app.delete('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
//   const { id } = req.params;

//   try {
//     const query = 'DELETE FROM feedback WHERE id = $1 RETURNING *';
//     const values = [id];

//     const result = await pool.query(query, values);

//     if (result.rowCount === 0) {
//       return res.status(404).json({ message: 'Feedback no encontrado' });
//     }

//     res.status(200).json({ message: 'Feedback eliminado correctamente', feedback: result.rows[0] });
//   } catch (error) {
//     console.error('Error al eliminar feedback:', error);
//     res.status(500).json({ message: 'Error al eliminar feedback' });
//   }
// });


//////////CONTROL FINANCIERO //////////////////////
app.delete('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Verificar si el feedback existe
    const verificarFeedbackQuery = 'SELECT * FROM feedback WHERE id = $1';
    const verificarFeedbackResult = await pool.query(verificarFeedbackQuery, [id]);

    if (verificarFeedbackResult.rowCount === 0) {
      return res.status(404).json({ message: 'Feedback no encontrado' });
    }

    // Eliminar el feedback
    const eliminarFeedbackQuery = 'DELETE FROM feedback WHERE id = $1 RETURNING *';
    const eliminarFeedbackResult = await pool.query(eliminarFeedbackQuery, [id]);

    res.status(200).json({
      message: 'Feedback eliminado correctamente',
      feedback: eliminarFeedbackResult.rows[0],
    });
  } catch (error) {
    console.error('Error al eliminar feedback:', error);
    res.status(500).json({ message: 'Error al eliminar feedback' });
  }
});



app.post('/ingresos', authenticateToken, async (req, res) => {
  const {
    tipo_ingreso,
    concepto,
    monto,
    tipo_moneda,
    tipo_ingreso_monetario,
    tipo_ingreso_donacion,
    fecha_ingreso,
    codigo_certificado,
    fecha_registro,
    benefactor_id,
    razon_social,
    ruc,
    lugar_recojo,
    ubicacion_actual,
  } = req.body;

  // console.log('Datos recibidos en el backend:', req.body); // <-- Depuración

  try {
    // Validar campos obligatorios generales
    if (!tipo_ingreso || !concepto || !fecha_ingreso || !codigo_certificado || !fecha_registro || !benefactor_id) {
      console.error('Error: Campos obligatorios generales incompletos'); // <-- Depuración
      return res.status(400).json({ message: 'Campos obligatorios generales incompletos.' });
    }

    // Validaciones específicas para tipo de ingreso: Monetario
    if (tipo_ingreso === 'monetario') {
      if (!monto || !tipo_moneda || !tipo_ingreso_monetario) {
        console.error('Error: Campos específicos de ingreso monetario incompletos'); // <-- Depuración
        return res.status(400).json({ message: 'Campos específicos de ingreso monetario incompletos.' });
      }
    }

    // Validaciones específicas para tipo de ingreso: Donaciones
    if (tipo_ingreso === 'donaciones') {
      if (!tipo_ingreso_donacion || !razon_social || !ruc || !lugar_recojo || !ubicacion_actual) {
        console.error('Error: Campos específicos de donaciones incompletos'); // <-- Depuración
        return res.status(400).json({ message: 'Campos específicos de donaciones incompletos.' });
      }

      // Validación específica para el RUC
      if (!/^\d{11}$/.test(ruc)) {
        console.error('Error: El RUC debe tener 11 dígitos'); // <-- Depuración
        return res.status(400).json({ message: 'El RUC debe tener 11 dígitos.' });
      }
    }

    // Construcción de la consulta SQL
    const query = `
      INSERT INTO ingresos (
        tipo_ingreso, concepto, monto, tipo_moneda, tipo_ingreso_monetario,
        tipo_ingreso_donacion, fecha_ingreso, codigo_certificado, fecha_registro,
        benefactor_id, razon_social, ruc, lugar_recojo, ubicacion_actual
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
      ) RETURNING *;
    `;
    const values = [
      tipo_ingreso,
      concepto,
      monto || null,
      tipo_moneda || null,
      tipo_ingreso_monetario || null,
      tipo_ingreso_donacion || null,
      fecha_ingreso,
      codigo_certificado,
      fecha_registro,
      benefactor_id,
      razon_social || null,
      ruc || null,
      lugar_recojo || null,
      ubicacion_actual || null,
    ];

    // Ejecución de la consulta en la base de datos
    const result = await pool.query(query, values);
    // console.log('Ingreso registrado exitosamente:', result.rows[0]); // <-- Depuración

    res.status(201).json({
      message: 'Ingreso registrado exitosamente.',
      ingreso: result.rows[0],
    });
  } catch (error) {
    console.error('Error al registrar ingreso:', error); // <-- Depuración
    res.status(500).json({ message: 'Error en el servidor al registrar ingreso.' });
  }
});


app.get('/ingresos', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
     SELECT ingresos.*,
       benefactores.nombre AS benefactor_nombre,
       COALESCE(v.nombre, 'Sin Asignar') AS voluntariado_asignado
        FROM ingresos
        LEFT JOIN benefactores ON ingresos.benefactor_id = benefactores.id
        LEFT JOIN (
            SELECT DISTINCT ON (ingreso_id) ingreso_id, voluntariados.nombre
            FROM ingresos_voluntariados
            JOIN voluntariados ON ingresos_voluntariados.voluntariado_id = voluntariados.id
            ORDER BY ingreso_id, asignado_en DESC
        ) v ON ingresos.id = v.ingreso_id
        ORDER BY ingresos.fecha_registro DESC;
    `);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error al listar ingresos:', error);
    res.status(500).json({ message: 'Error al listar ingresos.' });
  }
});

app.post('/ingresos/asignar-voluntariado', authenticateToken, async (req, res) => {
  const { ingreso_id, voluntariado_id, porcentaje } = req.body;

  if (!ingreso_id || !voluntariado_id || porcentaje === undefined) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }

  try {
    // Verificar si ya existe una asignación con el mismo ingreso y voluntariado
    const verificarAsignacionQuery = `
      SELECT * FROM ingresos_voluntariados
      WHERE ingreso_id = $1 AND voluntariado_id = $2;
    `;
    const verificarAsignacionValues = [ingreso_id, voluntariado_id];
    const verificarAsignacion = await pool.query(verificarAsignacionQuery, verificarAsignacionValues);

    if (verificarAsignacion.rows.length > 0) {
      return res.status(400).json({ message: 'Este ingreso ya está asignado a este voluntariado.' });
    }

    // Insertar la nueva asignación
    const insertarAsignacionQuery = `
      INSERT INTO ingresos_voluntariados (ingreso_id, voluntariado_id, porcentaje, asignado_en)
      VALUES ($1, $2, $3, NOW())
      RETURNING *;
    `;
    const insertarAsignacionValues = [ingreso_id, voluntariado_id, porcentaje];
    const result = await pool.query(insertarAsignacionQuery, insertarAsignacionValues);

    res.status(201).json({
      message: 'Voluntariado asignado correctamente.',
      asignacion: result.rows[0],
    });
  } catch (error) {
    console.error('Error al asignar voluntariado:', error);
    res.status(500).json({ message: 'Error al asignar voluntariado.' });
  }
});


app.put('/ingresos/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const {
    tipo_ingreso,
    concepto,
    monto,
    tipo_moneda,
    tipo_ingreso_monetario,
    tipo_ingreso_donacion,
    fecha_ingreso,
    codigo_certificado,
    benefactor_id,
    razon_social,
    ruc,
    lugar_recojo,
    ubicacion_actual,
  } = req.body;

  // console.log('Datos recibidos en el backend:', req.body);

  // Validaciones generales
  if (!tipo_ingreso || !concepto || !fecha_ingreso || !codigo_certificado || !benefactor_id) {
    return res.status(400).json({ message: 'Campos obligatorios generales incompletos.' });
  }

  try {
    let query = '';
    let values = [];

    if (tipo_ingreso === 'MONETARIO') {
      if (!monto || !tipo_moneda || !tipo_ingreso_monetario) {
        return res.status(400).json({ message: 'Campos específicos de ingreso monetario incompletos.' });
      }

      query = `
        UPDATE ingresos
        SET tipo_ingreso = $1, concepto = $2, fecha_ingreso = $3, codigo_certificado = $4, benefactor_id = $5,
        monto = $6, tipo_moneda = $7, tipo_ingreso_monetario = $8
        WHERE id = $9 RETURNING *;
      `;
      values = [tipo_ingreso, concepto, fecha_ingreso, codigo_certificado, benefactor_id, monto, tipo_moneda, tipo_ingreso_monetario, id];
    } else if (tipo_ingreso === 'DONACIONES') {
      if (!tipo_ingreso_donacion || !razon_social || !ruc || !lugar_recojo || !ubicacion_actual) {
        return res.status(400).json({ message: 'Campos específicos de donaciones incompletos.' });
      }

      query = `
        UPDATE ingresos
        SET tipo_ingreso = $1, concepto = $2, fecha_ingreso = $3, codigo_certificado = $4, benefactor_id = $5,
        tipo_ingreso_donacion = $6, razon_social = $7, ruc = $8, lugar_recojo = $9, ubicacion_actual = $10
        WHERE id = $11 RETURNING *;
      `;
      values = [
        tipo_ingreso,
        concepto,
        fecha_ingreso,
        codigo_certificado,
        benefactor_id,
        tipo_ingreso_donacion,
        razon_social,
        ruc,
        lugar_recojo,
        ubicacion_actual,
        id,
      ];
    } else {
      return res.status(400).json({ message: 'Tipo de ingreso no válido.' });
    }

    // console.log('Campos para la consulta:', query);
    // console.log('Valores para la consulta:', values);

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Ingreso no encontrado.' });
    }

    // console.log('Ingreso actualizado exitosamente:', result.rows[0]);
    res.status(200).json({ message: 'Ingreso actualizado exitosamente.', ingreso: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar ingreso:', error);
    res.status(500).json({ message: 'Error al actualizar ingreso.' });
  }
});





app.get('/ingresos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(`
      SELECT ingresos.*,
             benefactores.nombre AS benefactor_nombre
      FROM ingresos
      LEFT JOIN benefactores ON ingresos.benefactor_id = benefactores.id
      WHERE ingresos.id = $1;
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Ingreso no encontrado.' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener ingreso:', error);
    res.status(500).json({ message: 'Error al obtener ingreso.' });
  }
});

////////// CONTROL FINANCIERO: PRODUCTOS //////////////////////


// Registrar producto
app.post('/ingresos/:ingresoId/productos', authenticateToken, async (req, res) => {
  const { ingresoId } = req.params;
  const {
    nombre_producto,
    cantidad,
    tipo_unidad,
    tipo_producto,
    fecha_vencimiento,
    registro_sanitario,
    motivo,
    costo_unidad,
    costo_total,
    numero_lote,
    estado,
  } = req.body;

  // console.log('Datos recibidos en el backend:', req.body);

  try {
    // Validar campos obligatorios
    if (
      !nombre_producto ||
      !cantidad ||
      !tipo_unidad ||
      !tipo_producto ||
      !costo_unidad ||
      !costo_total ||
      !estado
    ) {
      return res.status(400).json({ message: 'Campos obligatorios incompletos.' });
    }

    // Validaciones específicas para alimentos
    if (tipo_producto === 'alimentación' && (!fecha_vencimiento || !registro_sanitario)) {
      return res
        .status(400)
        .json({ message: 'Los alimentos requieren fecha de vencimiento y registro sanitario.' });
    }

    const query = `
      INSERT INTO productos (
        ingreso_id, nombre_producto, cantidad, tipo_unidad, tipo_producto,
        fecha_vencimiento, registro_sanitario, motivo, costo_unidad,
        costo_total, numero_lote, estado
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      ) RETURNING *;
    `;
    const values = [
      ingresoId,
      nombre_producto,
      cantidad,
      tipo_unidad,
      tipo_producto,
      fecha_vencimiento || null,
      registro_sanitario || null,
      motivo || null,
      costo_unidad,
      costo_total,
      numero_lote || null,
      estado,
    ];

    const result = await pool.query(query, values);
    res.status(201).json({
      message: 'Producto registrado exitosamente.',
      producto: result.rows[0],
    });
  } catch (error) {
    console.error('Error al registrar producto:', error);
    res.status(500).json({ message: 'Error al registrar producto.' });
  }
});

// Editar producto
app.get('/ingresos/:ingresoId/productos/:productoId', authenticateToken, async (req, res) => {
  const { ingresoId, productoId } = req.params;

  try {
    const query = `
      SELECT *
      FROM productos
      WHERE ingreso_id = $1 AND id = $2;
    `;
    const values = [ingresoId, productoId];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Producto no encontrado.' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener producto:', error);
    res.status(500).json({ message: 'Error al obtener producto.' });
  }
});


app.put('/ingresos/:ingresoId/productos/:productoId', authenticateToken, async (req, res) => {
  const { ingresoId, productoId } = req.params;
  const {
    nombre_producto,
    cantidad,
    tipo_unidad,
    tipo_producto,
    fecha_vencimiento,
    registro_sanitario,
    motivo,
    costo_unidad,
    costo_total,
    numero_lote,
    estado,
  } = req.body;

  // console.log('Datos recibidos para actualizar:', req.body);

  try {
    // Validar campos obligatorios comunes
    const camposObligatorios = [
      nombre_producto,
      cantidad,
      tipo_unidad,
      tipo_producto,
      costo_unidad,
      costo_total,
      estado,
    ];

    if (camposObligatorios.some((campo) => campo === undefined || campo === null || campo === '')) {
      return res.status(400).json({ message: 'Campos obligatorios incompletos.' });
    }

    // Validaciones específicas para alimentos
    if (tipo_producto === 'alimentación') {
      if (!fecha_vencimiento || !registro_sanitario) {
        return res.status(400).json({
          message: 'Los alimentos requieren fecha de vencimiento y registro sanitario.',
        });
      }
    }

    const query = `
      UPDATE productos
      SET
        nombre_producto = $1,
        cantidad = $2,
        tipo_unidad = $3,
        tipo_producto = $4,
        fecha_vencimiento = $5,
        registro_sanitario = $6,
        motivo = $7,
        costo_unidad = $8,
        costo_total = $9,
        numero_lote = $10,
        estado = $11
      WHERE ingreso_id = $12 AND id = $13
      RETURNING *;
    `;

    const values = [
      nombre_producto,
      cantidad,
      tipo_unidad,
      tipo_producto,
      fecha_vencimiento || null,
      registro_sanitario || null,
      motivo || null,
      costo_unidad,
      costo_total,
      numero_lote || null,
      estado,
      ingresoId,
      productoId,
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Producto no encontrado.' });
    }

    res.status(200).json({
      message: 'Producto actualizado exitosamente.',
      producto: result.rows[0],
    });
  } catch (error) {
    console.error('Error al actualizar producto:', error);
    res.status(500).json({ message: 'Error al actualizar producto.' });
  }
});


// Listar productos por ingreso
app.get('/gastos', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT
        gastos.id,
        gastos.descripcion,
        gastos.importe,
        voluntariados.nombre AS voluntariado_nombre, -- Trae el nombre del voluntariado
        gastos.fecha_gasto,
        gastos.nro_comprobante,
        gastos.tipo_comprobante,
        gastos.fecha_registro,
        gastos.tipo_gasto,
        gastos.ruc_dni,
        gastos.razon_social_nombre,
        gastos.observacion,
        gastos.created_at,
        gastos.updated_at
      FROM gastos
      INNER JOIN voluntariados ON gastos.voluntariado_id = voluntariados.id -- Relación con voluntariados
      ORDER BY gastos.created_at DESC;
    `;
    const result = await pool.query(query);
    res.status(200).json(result.rows); // Devuelve los datos al cliente
  } catch (error) {
    console.error('Error al obtener la lista de gastos:', error);
    res.status(500).json({ message: 'Error al obtener la lista de gastos.' });
  }
});

app.get('/gastos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
      SELECT
        gastos.id,
        gastos.descripcion,
        gastos.importe,
        gastos.voluntariado_id,
        voluntariados.nombre AS voluntariado_nombre,
        gastos.fecha_gasto,
        gastos.nro_comprobante,
        gastos.tipo_comprobante,
        gastos.tipo_gasto,
        gastos.ruc_dni,
        gastos.razon_social_nombre,
        gastos.observacion
      FROM gastos
      LEFT JOIN voluntariados ON gastos.voluntariado_id = voluntariados.id
      WHERE gastos.id = $1;
    `;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Gasto no encontrado.' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener el gasto:', error);
    res.status(500).json({ message: 'Error al obtener el gasto.' });
  }
});



app.post('/gastos', authenticateToken, async (req, res) => {
  const {
    descripcion,
    importe,
    voluntariado_asignado,
    fecha_gasto,
    nro_comprobante,
    tipo_comprobante,
    fecha_registro, // Este campo puede ser opcional
    tipo_gasto,
    ruc_dni,
    razon_social_nombre, // Corregido para coincidir con el nombre de la tabla
    observacion
  } = req.body;

  try {
    // Si no se proporciona fecha_registro, usa la fecha actual
    const fechaRegistro = fecha_registro || new Date().toISOString().split('T')[0];

    const query = `
      INSERT INTO gastos (descripcion, importe, voluntariado_id, fecha_gasto, nro_comprobante, tipo_comprobante, fecha_registro, tipo_gasto, ruc_dni, razon_social_nombre, observacion)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *;
    `;
    const values = [descripcion, importe, voluntariado_asignado, fecha_gasto, nro_comprobante, tipo_comprobante, fechaRegistro, tipo_gasto, ruc_dni, razon_social_nombre, observacion];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error al registrar gasto:', error);
    res.status(500).json({ message: 'Error al registrar gasto.' });
  }
});



app.get('/ingresos/:ingresoId/productos', authenticateToken, async (req, res) => {
  const { ingresoId } = req.params;

  try {
    const query = `
      SELECT id as idProducto,nombre_producto, cantidad, tipo_unidad, tipo_producto,
             fecha_vencimiento, registro_sanitario, estado
      FROM productos
      WHERE ingreso_id = $1
      ORDER BY created_at DESC;
    `;
    const result = await pool.query(query, [ingresoId]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error al listar productos:', error);
    res.status(500).json({ message: 'Error al listar productos.' });
  }
});




/////////////////////gASTOS ////////////////////////



app.put('/gastos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    descripcion,
    importe,
    voluntariado_id,
    fecha_gasto,
    nro_comprobante,
    tipo_comprobante,
    tipo_gasto,
    ruc_dni,
    razon_social_nombre,
    observacion
  } = req.body;

  try {
    const query = `
      UPDATE gastos
      SET
        descripcion = $1,
        importe = $2,
        voluntariado_id = $3,
        fecha_gasto = $4,
        nro_comprobante = $5,
        tipo_comprobante = $6,
        tipo_gasto = $7,
        ruc_dni = $8,
        razon_social_nombre = $9,
        observacion = $10,
        updated_at = NOW()
      WHERE id = $11
      RETURNING *;
    `;
    const values = [
      descripcion,
      importe,
      voluntariado_id,
      fecha_gasto,
      nro_comprobante,
      tipo_comprobante,
      tipo_gasto,
      ruc_dni,
      razon_social_nombre,
      observacion,
      id
    ];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Gasto no encontrado.' });
    }

    res.status(200).json({ message: 'Gasto actualizado exitosamente.', gasto: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar el gasto:', error);
    res.status(500).json({ message: 'Error al actualizar el gasto.' });
  }
});



app.put('/restaurar-contrasena', authenticateToken, async (req, res) => {
  const { tabla, id } = req.body; // Recibe la tabla y el id desde el frontend

  try {
    // Validar que solo se permita modificar en las tablas permitidas
    if (!['usuarios', 'voluntarios'].includes(tabla)) {
      return res.status(400).json({ message: 'Tabla no permitida.' });
    }

    // Validar que el ID sea un número válido
    if (!id || isNaN(id)) {
      return res.status(400).json({ message: 'ID inválido.' });
    }

    // Obtener el DNI del registro
    const queryObtenerDNI = `SELECT dni FROM ${tabla} WHERE id = $1`;
    const resultado = await pool.query(queryObtenerDNI, [id]);

    if (resultado.rows.length === 0) {
      return res.status(404).json({ message: 'Registro no encontrado.' });
    }

    const dni = resultado.rows[0].dni; // Extrae el DNI del registro

    // Encriptar la nueva contraseña (DNI)
    const saltRounds = 10; // Número de rondas de sal
    const passwordEncriptado = await bcrypt.hash(dni, saltRounds);

    // Actualizar la contraseña en la base de datos
    const queryActualizar = `
      UPDATE ${tabla}
      SET password = $1
      WHERE id = $2
    `;
    const resultadoActualizar = await pool.query(queryActualizar, [passwordEncriptado, id]);

    if (resultadoActualizar.rowCount === 0) {
      return res.status(404).json({ message: 'No se pudo actualizar la contraseña.' });
    }

    res.status(200).json({ message: 'Contraseña restaurada correctamente.' });
  } catch (error) {
    console.error('Error al restaurar contraseña:', error);
    res.status(500).json({ message: 'Error al restaurar la contraseña.' });
  }
});






module.exports = app;

