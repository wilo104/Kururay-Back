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


const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bdKururay',
    password: 'alohomora',
    port: 5432,
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads');
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage });
const readFileAsync = util.promisify(fs.readFile);

// Login
// app.post('/login', async (req, res) => {
//   const { dni, password } = req.body;

//   try {
//     if (!dni || !password) {
//       return res.status(400).json({ message: 'Ingrese DNI y contraseña' });
//     }

//     // Consultar en la tabla usuarios
//     let userQuery = await pool.query('SELECT id, dni, password, tipo_usuario, estado_usuario FROM usuarios WHERE dni = $1', [dni]);

//     if (userQuery.rows.length === 0) {
//       // Si no se encuentra en `usuarios`, buscar en `voluntarios`
//       userQuery = await pool.query('SELECT id, dni, password FROM voluntarios WHERE dni = $1', [dni]);

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
//         { id: userQuery.rows[0].id, dni: userQuery.rows[0].dni, tipo_usuario: 'VOLUNTARIO' },
//         process.env.JWT_SECRET || 'tu_secreto_secreto'
//       );

//       return res.json({
//         token,
//         tipo_usuario: 'VOLUNTARIO',
//         id: userQuery.rows[0].id,
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
//       { id: userQuery.rows[0].id, dni: userQuery.rows[0].dni, tipo_usuario: userQuery.rows[0].tipo_usuario },
//       process.env.JWT_SECRET || 'tu_secreto_secreto'
//     );

//     res.json({
//       token,
//       tipo_usuario: userQuery.rows[0].tipo_usuario,
//       id: userQuery.rows[0].id,
//     });
//   } catch (error) {
//     console.error('Error en la autenticación:', error);
//     res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
//   }
// });

app.post('/login', async (req, res) => {
  const { dni, password } = req.body;

  try {
    if (!dni || !password) {
      return res.status(400).json({ message: 'Ingrese DNI y contraseña' });
    }

    // Consultar en la tabla usuarios
    let userQuery = await pool.query(
      `SELECT id, dni, password, tipo_usuario, estado_usuario, 
      (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo 
      FROM usuarios WHERE dni = $1`,
      [dni]
    );

    if (userQuery.rows.length === 0) {
      // Si no se encuentra en `usuarios`, buscar en `voluntarios`
      userQuery = await pool.query(
        `SELECT id, dni, password, 
        (nombre || ' ' || apellido_paterno || ' ' || apellido_materno) AS nombre_completo 
        FROM voluntarios WHERE dni = $1`,
        [dni]
      );

      if (userQuery.rows.length === 0) {
        return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
      }

      const storedPasswordHash = userQuery.rows[0].password;

      // Comparar contraseñas
      if (!(await bcrypt.compare(password, storedPasswordHash))) {
        return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
      }

      // Generar token JWT para voluntario
      const token = jwt.sign(
        {
          id: userQuery.rows[0].id,
          dni: userQuery.rows[0].dni,
          tipo_usuario: 'VOLUNTARIO',
        },
        process.env.JWT_SECRET || 'tu_secreto_secreto'
      );

      return res.json({
        token,
        tipo_usuario: 'VOLUNTARIO',
        id: userQuery.rows[0].id,
        nombre_completo: userQuery.rows[0].nombre_completo, // Nombre completo del voluntario
      });
    }

    // Si el usuario está en la tabla `usuarios`, verificar contraseña
    const storedPasswordHash = userQuery.rows[0].password;

    if (!(await bcrypt.compare(password, storedPasswordHash))) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    if (!userQuery.rows[0].estado_usuario) {
      return res.status(403).json({ message: 'Cuenta inactiva. Contacte al administrador.' });
    }

    // Generar token JWT para usuario
    const token = jwt.sign(
      {
        id: userQuery.rows[0].id,
        dni: userQuery.rows[0].dni,
        tipo_usuario: userQuery.rows[0].tipo_usuario,
      },
      process.env.JWT_SECRET || 'tu_secreto_secreto'
    );

    res.json({
      token,
      tipo_usuario: userQuery.rows[0].tipo_usuario,
      id: userQuery.rows[0].id,
      nombre_completo: userQuery.rows[0].nombre_completo, // Nombre completo del usuario
    });
  } catch (error) {
    console.error('Error en la autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
  }
});







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
app.put('/usuarios/:id/cambiar-contrasena', authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id); // ID del usuario pasado en la URL
  const { contrasenaActual, nuevaContrasena } = req.body;

  try {
    // Verificar si el usuario autenticado es el mismo que el que intenta cambiar la contraseña
    if (req.user.id !== userId) {
      return res.status(403).json({ message: 'No tiene permisos para cambiar esta contraseña' });
    }

    // Verificar si el usuario existe
    const userQuery = await pool.query('SELECT password FROM usuarios WHERE id = $1', [userId]);
    const usuario = userQuery.rows[0];

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña actual
    const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
    if (!contrasenaValida) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }

    // Generar el hash de la nueva contraseña
    const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

    // Actualizar la contraseña
    await pool.query('UPDATE usuarios SET password = $1 WHERE id = $2', [nuevaContrasenaHash, userId]);
    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error al cambiar contraseña:', error);
    res.status(500).json({ message: 'Error al cambiar la contraseña' });
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

app.get('/voluntarios', async (req, res) => {
  try {
    const query = `
      SELECT *FROM voluntarios
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

app.put('/voluntarios/:id/cambiar-contrasena', authenticateToken, async (req, res) => {
  const voluntarioId = parseInt(req.params.id); // ID del voluntario pasado en la URL
  const { contrasenaActual, nuevaContrasena } = req.body;

  try {
    // Verificar si el voluntario autenticado es el mismo que intenta cambiar la contraseña
    if (req.user.id !== voluntarioId) {
      return res.status(403).json({ message: 'No tiene permisos para cambiar esta contraseña' });
    }

    // Verificar si el voluntario existe
    const voluntarioQuery = await pool.query('SELECT password FROM voluntarios WHERE id = $1', [voluntarioId]);
    const voluntario = voluntarioQuery.rows[0];

    if (!voluntario) {
      return res.status(404).json({ message: 'Voluntario no encontrado' });
    }

    // Verificar la contraseña actual
    const contrasenaValida = await bcrypt.compare(contrasenaActual, voluntario.password);
    if (!contrasenaValida) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }

    // Generar el hash de la nueva contraseña
    const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

    // Actualizar la contraseña en la base de datos
    await pool.query('UPDATE voluntarios SET password = $1 WHERE id = $2', [nuevaContrasenaHash, voluntarioId]);

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error al cambiar la contraseña del voluntario:', error);
    res.status(500).json({ message: 'Error en el servidor al cambiar la contraseña del voluntario' });
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




// Endpoint para cambiar la contraseña de un usuario o voluntario
app.put('/:tabla/:id/cambiar-contrasena', async (req, res) => {
  const { tabla, id } = req.params; // La tabla puede ser "usuarios" o "voluntarios"
  const { contrasenaActual, nuevaContrasena } = req.body;

  if (!['usuarios', 'voluntarios'].includes(tabla)) {
    return res.status(400).json({ message: 'Tabla no válida. Use usuarios o voluntarios.' });
  }

  try {
    // Verificar si el registro existe
    const query = `SELECT * FROM ${tabla} WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: `${tabla.slice(0, -1)} no encontrado` });
    }

    const usuario = result.rows[0];

    // Verificar la contraseña actual
    const contrasenaValida = await bcrypt.compare(contrasenaActual, usuario.password);
    if (!contrasenaValida) {
      return res.status(401).json({ message: 'Contraseña actual incorrecta' });
    }

    // Hashear la nueva contraseña
    const nuevaContrasenaHash = await bcrypt.hash(nuevaContrasena, 10);

    // Actualizar la contraseña en la base de datos
    const updateQuery = `UPDATE ${tabla} SET password = $1 WHERE id = $2`;
    await pool.query(updateQuery, [nuevaContrasenaHash, id]);

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error(`Error al actualizar la contraseña del ${tabla.slice(0, -1)}:`, error);
    res.status(500).json({ message: `Error al actualizar la contraseña del ${tabla.slice(0, -1)}` });
  }
});

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
  const { id } = req.params; // Obtén el ID del voluntario de los parámetros de la URL

  try {
    const query = `
      SELECT 
        v.id AS id_voluntariado,
        v.nombre,
        CONCAT(vol.nombre, ' ', vol.apellido_paterno, ' ', vol.apellido_materno) AS nombre_completo,
        v.lugar,
        v.descripcion,
        va.fecha_asignacion
      FROM 
        voluntariados v
      JOIN 
        voluntarios_asignados va ON v.id = va.id_voluntariado
      JOIN 
        voluntarios vol ON va.id_voluntario = vol.id
      WHERE 
        vol.id = $1; -- Filtra por el ID del voluntario
    `;

    // Ejecuta la consulta SQL
    const result = await pool.query(query, [id]);

    // Si no se encuentran resultados
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontraron voluntariados para este voluntario' });
    }

    // Si se encuentran resultados, devolverlos
    res.json(result.rows);
  } catch (error) {
    // Manejo de errores
    console.error('Error al obtener historial:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el historial' });
  }
});

//Obtener feedback de un voluntariado específico
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
        v.id AS voluntariado_id,
        v.nombre AS voluntariado_nombre
      FROM feedback fb
      JOIN voluntarios_asignados va ON fb.id_voluntario = va.id_voluntario
      JOIN voluntariados v ON va.id_voluntariado = v.id
      WHERE fb.id_voluntario = $1
      ORDER BY fb.fecha;
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

function authenticateToken(req, res, next) {
  const token = req.get('Authorization')?.split(' ')[1];
 

  if (!token) {
    console.warn('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'tu_secreto_secreto', (err, user) => {
    if (err) {
      console.error('Error de verificación de token:', err);
      return res.status(403).json({ message: 'Token no válido' });
    }



    if (!user || !user.id || !user.tipo_usuario) {
      console.warn('Información incompleta en el token:', user);
      return res.status(403).json({ message: 'El token no contiene información completa del usuario' });
    }

    req.user = user; // Almacenar el usuario decodificado
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
    const totalVoluntarios = parseInt(totalVoluntariosResult.rows[0].total_voluntarios) || 0;

    // Calcular la asistencia de los voluntarios
    const asistenciaQuery = `
      SELECT
        COUNT(CASE WHEN estado = 'Presente' THEN 1 END) AS asistentes_voluntarios
      FROM estado_asistencia ea
      JOIN asistencias a ON ea.asistencia_id = a.id
      WHERE a.id_voluntariado = $1
    `;
    const asistenciaResult = await pool.query(asistenciaQuery, [id]);
    const asistentesVoluntarios = parseInt(asistenciaResult.rows[0].asistentes_voluntarios) || 0;

    // Calcular el porcentaje de participación
    let porcentajeParticipacion = 0;
    if (totalVoluntarios > 0) {
      porcentajeParticipacion = (asistentesVoluntarios / totalVoluntarios) * 100;
    }

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












app.get('/voluntariados/:id/asistencias', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT id, fecha_asistencia, total_asistentes
      FROM asistencias
      WHERE id_voluntariado = $1
    `;
    const result = await pool.query(query, [id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener asistencias:', error);
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

app.post('/voluntarios/feedback', authenticateToken, async (req, res) => {
  const { id_voluntario, fecha, adicional, mentor, descripcion, tipo } = req.body;

  try {
      if (!id_voluntario || !fecha || !mentor || !descripcion || !tipo) {
          return res.status(400).json({ message: 'Todos los campos obligatorios deben ser completados.' });
      }

      const query = `
          INSERT INTO feedback (id_voluntario, fecha, adicional, mentor, descripcion, tipo)
          VALUES ($1, $2, $3, $4, $5, $6)
          RETURNING *;
      `;
      const values = [id_voluntario, fecha, adicional || null, mentor, descripcion, tipo];

      const result = await pool.query(query, values);
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

app.delete('/voluntarios/feedback/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const query = 'DELETE FROM feedback WHERE id = $1 RETURNING *';
    const values = [id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Feedback no encontrado' });
    }

    res.status(200).json({ message: 'Feedback eliminado correctamente', feedback: result.rows[0] });
  } catch (error) {
    console.error('Error al eliminar feedback:', error);
    res.status(500).json({ message: 'Error al eliminar feedback' });
  }
});




app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});