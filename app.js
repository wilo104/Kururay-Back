const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors'); // Importa el middleware cors

const path = require('path');
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
    const clave_dni = password === userQuery.rows[0].dni; // Esta línea reemplaza tu implementación de clave_dni
 
    // Generar el token JWT con un secreto seguro
    const token = jwt.sign(
      { id: userQuery.rows[0].id, dni: userQuery.rows[0].dni, tipo_usuario: userQuery.rows[0].tipo_usuario },
      process.env.JWT_SECRET || 'tu_secreto_secreto'
    );

    // Incluir el rol y el ID en la respuesta
    const tipo_usuario = userQuery.rows[0].tipo_usuario;
    const id = userQuery.rows[0].id; // Obtener el ID del usuario de la consulta

    res.json({ token, tipo_usuario, id, clave_dni }); // Incluir el ID en la respuesta JSON
  } catch (error) {
    console.error('Error en la autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor durante la autenticación' });
  }
});



app.get('/usuarios', async (req, res) => {
  // Lista blanca de columnas y direcciones permitidas
  const columnasPermitidas = ['id', 'nombre', 'apellido_paterno', 'correo', 'telefono'];
  const direccionPermitida = ['ASC', 'DESC'];

  // Obtener parámetros de consulta
  let { ordenPor, direccion } = req.query;

  // Validar columna (por defecto: 'id')
  ordenPor = columnasPermitidas.includes(ordenPor) ? ordenPor : 'id';

  // Validar dirección (por defecto: 'ASC')
  if (typeof direccion === 'string') {
    direccion = direccion.toUpperCase(); // Convertir a mayúsculas si existe
    direccion = direccionPermitida.includes(direccion) ? direccion : 'ASC';
  } else {
    direccion = 'ASC'; // Asignar valor predeterminado
  }

  try {
    // Realizar consulta a la base de datos
    const query = `SELECT * FROM usuarios ORDER BY ${ordenPor} ${direccion}`;
    const result = await pool.query(query);

    // Responder con los resultados
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener usuarios:', error.message);
    res.status(500).json({
      message: 'Error en el servidor al obtener usuarios',
      error: error.message, // Información extra (opcional)
    });
  }
});


// app.get('/usuarios/:id/cv', async (req, res) => {
//   const userId = req.params.id;

//   try {
//     // Buscar el usuario en la base de datos
//     const userQuery = await pool.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
//     const usuario = userQuery.rows[0];

//     if (!usuario) {
//       return res.status(404).json({ message: 'Usuario no encontrado' });
//     }

//     // Verificar si el usuario tiene un CV
//     if (!usuario.cv) {
//       return res.status(404).json({ message: 'CV no encontrado para este usuario' });
//     }
//     console.log('Ruta del archivo CV:', usuario.cv);
//     // Leer el archivo CV desde la ubicación donde multer lo almacenó
//     const cvContent = await readFileAsync(usuario.cv);
 
//     // Devolver el contenido del CV como respuesta
//     res.setHeader('Content-Type', 'application/pdf'); // Por ejemplo, si el CV es un PDF
//     res.send(cvContent);
//   } catch (error) {
//     console.error('Error al obtener el CV del usuario:', error);
//     res.status(500).json({ message: 'Error al obtener el CV del usuario', error: error.message });
//   }
// });
// Endpoint para obtener un usuario específico por ID
app.get('/usuarios/:id/cv', async (req, res) => {
  const userId = req.params.id;

  try {
    // Obtener el contenido del archivo CV como un búfer de bytes desde la base de datos
    const userQuery = await pool.query('SELECT cv FROM usuarios WHERE id = $1', [userId]);
    const cvFileBuffer = userQuery.rows[0].cv;

    // Devolver el contenido del CV como respuesta
    res.setHeader('Content-Type', 'application/pdf');
    res.send(cvFileBuffer);
  } catch (error) {
    console.error('Error al obtener el CV del usuario:', error);
    res.status(500).json({ message: 'Error al obtener el CV del usuario' });
  }
});
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



const multer = require('multer');
// const upload = multer({ dest: 'uploads/' }); 
const fs = require('fs');
const util = require('util');
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads'); // Directorio donde se guardarán los archivos
  },
  filename: function (req, file, cb) {
    // Utiliza un nombre de archivo único para evitar colisiones
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });
// Promisificar fs.readFile
const readFileAsync = util.promisify(fs.readFile);

// app.post('/usuarios/registro', upload.single('cv'), async (req, res) => {
//   try {
//     const cvFile = req.file ? req.file.path : null; // Ruta del archivo CV en el servidor
//     console.log('Valor de req.file:', req.file);
//     const {
//       dni,
//       nombre,
//       correo,
//       telefono,
//       tipo_usuario,
//       apellido_paterno,
//       apellido_materno,
//       fecha_nacimiento,
//       area,
//       rol,
//       categoria,
//       fecha_ingreso,
//       situacion,
//       carrera,
//       instagram,
//       facebook,
//       linkedin
//     } = req.body;
//     console.log('Valor de cvFile:', cvFile);
//     // Validar campos
//     const validationErrors = [];
//     if (!dni || dni.length !== 8 || !/^\d{8}$/.test(dni)) {
//       validationErrors.push('El DNI debe ser de 8 dígitos numéricos y es obligatorio');
//     }
//     if (!nombre) {
//       validationErrors.push('El nombre es obligatorio');
//     }
//     if (!apellido_paterno) {
//       validationErrors.push('El apellido paterno es obligatorio');
//     }
//     if (!apellido_materno) {
//       validationErrors.push('El apellido materno es obligatorio');
//     }
//     if (!correo || !/\S+@\S+\.\S+/.test(correo)) {
//       validationErrors.push('El correo es inválido o está vacío');
//     }
//     if (!telefono || telefono.length !== 9 || !/^\d{9}$/.test(telefono)) {
//       validationErrors.push('El teléfono debe ser de 9 dígitos numéricos y es obligatorio');
//     }
//     if (!fecha_nacimiento) {
//       validationErrors.push('La fecha de nacimiento es obligatoria');
//     }
//     if (!area) {
//       validationErrors.push('El área es obligatoria');
//     }
//     if (!rol) {
//       validationErrors.push('El rol es obligatorio');
//     }
//     if (!categoria) {
//       validationErrors.push('La categoría es obligatoria');
//     }
//     if (!fecha_ingreso) {
//       validationErrors.push('La fecha de ingreso es obligatoria');
//     }
//     if (!situacion) {
//       validationErrors.push('La situación Academica es obligatoria');
//     }
//     if (!carrera) {
//       validationErrors.push('La carrera es obligatoria');
//     }

//     if (validationErrors.length > 0) {
//       return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
//     }

//     // Verificar si el usuario ya existe en la base de datos
//     const userExistsQuery = await pool.query('SELECT * FROM usuarios WHERE dni = $1', [dni]);
//     if (userExistsQuery.rows.length > 0) {
//       return res.status(400).json({ message: 'El usuario ya está registrado' });
//     }

//     // Generar código de voluntario
//     const fechaIngresoYear = new Date(fecha_ingreso).getFullYear();
//     const categoriaAbbreviation = categoria.substring(0, 3).toUpperCase();
//     const areaAbbreviation = area.substring(0, 3).toUpperCase();
//     const codigo = `${fechaIngresoYear}_${categoriaAbbreviation}_${areaAbbreviation}`;

//     // Usar el DNI como clave inicial
//     const hashedPassword = await bcrypt.hash(dni, 10);

//     // Leer el archivo CV como un búfer de bytes
//     let cvBuffer = null;
//     if (cvFile) {
//       cvBuffer = await readFileAsync(cvFile);
//       console.log('Contenido del CV como búfer de bytes:', cvBuffer); // Agregar esta línea para verificar el contenido de cvBuffer


//     }
//     console.log(cvFile);
//     console.log(cvBuffer);
//     // Insertar el nuevo usuario en la base de datos
//     const insertQuery = await pool.query(
//       'INSERT INTO usuarios (dni, nombre, password, correo, telefono, tipo_usuario, estado_usuario, apellido_paterno, apellido_materno, fecha_nacimiento, area, rol, categoria, fecha_ingreso, grado_instruccion, carrera, instagram, facebook, linkedin, codigo, cv) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)',
//       [dni, nombre, hashedPassword, correo, telefono, tipo_usuario, true, apellido_paterno, apellido_materno, fecha_nacimiento, area, rol, categoria, fecha_ingreso, situacion, carrera, instagram, facebook, linkedin, codigo, cvBuffer]
//     );

//     // Redirigir a la pantalla de listado de usuarios con un mensaje de éxito y mostrar modal
//     res.json({ message: 'Registrado correctamente', modal: 'Registrado' });

//   } catch (error) {
//     console.error('Error en el registro de usuario:', error);
//     res.status(500).json({ message: 'No es posible realizar el registro' });
//   }
// });
app.post('/usuarios/registro', upload.single('cv'), async (req, res) => {
  try {
    const cvFile = req.file ? req.file.path : null; // Ruta del archivo CV en el servidor
    console.log('Valor de req.file:', req.file);
    const {
      dni,
      nombre,
      correo,
      telefono,
      tipo_usuario,
      apellido_paterno,
      apellido_materno,
      fecha_nacimiento,
      area,
      rol,
      categoria,
      fecha_ingreso,
      situacion,
      carrera,
      instagram,
      facebook,
      linkedin
    } = req.body;
    console.log('Valor de cvFile:', cvFile);
    // Validar campos
    const validationErrors = [];
    if (!dni || dni.length !== 8 || !/^\d{8}$/.test(dni)) {
      validationErrors.push('El DNI debe ser de 8 dígitos numéricos y es obligatorio');
    }
    if (!nombre) {
      validationErrors.push('El nombre es obligatorio');
    }
    // Validar los demás campos...

    if (validationErrors.length > 0) {
      return res.status(400).json({ message: 'Errores de validación', errors: validationErrors });
    }

    // Verificar si el usuario ya existe en la base de datos
    const userExistsQuery = await pool.query('SELECT * FROM usuarios WHERE dni = $1', [dni]);
    if (userExistsQuery.rows.length > 0) {
      return res.status(400).json({ message: 'El usuario ya está registrado' });
    }

    // Generar código de voluntario
    const fechaIngresoYear = new Date(fecha_ingreso).getFullYear();
    const categoriaAbbreviation = categoria.substring(0, 3).toUpperCase();
    const areaAbbreviation = area.substring(0, 3).toUpperCase();
    const codigo = `${fechaIngresoYear}_${categoriaAbbreviation}_${areaAbbreviation}`;

    // Usar el DNI como clave inicial
    const hashedPassword = await bcrypt.hash(dni, 10);

    // Leer el archivo CV como un búfer de bytes
    let cvBuffer = null;
    if (cvFile) {
      cvBuffer = await readFileAsync(cvFile);
      console.log('Contenido del CV como búfer de bytes:', cvBuffer); // Agregar esta línea para verificar el contenido de cvBuffer
    }

    // Insertar el nuevo usuario en la base de datos
    const insertQuery = await pool.query(
      'INSERT INTO usuarios (dni, nombre, password, correo, telefono, tipo_usuario, estado_usuario, apellido_paterno, apellido_materno, fecha_nacimiento, area, rol, categoria, fecha_ingreso, grado_instruccion, carrera, instagram, facebook, linkedin, codigo, cv) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)',
      [dni, nombre, hashedPassword, correo, telefono, tipo_usuario, true, apellido_paterno, apellido_materno, fecha_nacimiento, area, rol, categoria, fecha_ingreso, situacion, carrera, instagram, facebook, linkedin, codigo, cvBuffer]
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
  const { nombre, apellido_paterno,apellido_materno,correo, telefono, tipo_usuario } = req.body;

  try {
    // Verificar si el usuario existe en la base de datos
    const userQuery = await pool.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    const usuario = userQuery.rows[0];

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Actualizar la información del usuario
    await pool.query(
      'UPDATE usuarios SET nombre = $1, correo = $2, telefono = $3, tipo_usuario = $4,apellido_materno=$5,apellido_paterno=$6 WHERE id = $7',
      [nombre, correo, telefono, tipo_usuario,apellido_materno,apellido_paterno, userId]
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

app.get('/voluntarios', async (req, res) => {
  try {
      const result = await pool.query("select *from usuarios WHERE tipo_usuario='VOLUNTARIO'");
      res.json(result.rows);
  } catch (error) {
      console.error('Error al obtener voluntarios:', error);
      res.status(500).json({ message: 'Error en el servidor al obtener voluntarios' });
  }
});



// Obtener historial de voluntariados para un voluntario
// app.get('/voluntarios/:id/historial', async (req, res) => {
//   const { id } = req.params; // Obtén el ID de los parámetros de la URL
//   try {
//     const query = `
//       SELECT 
//         v.id,
//         u.nombre, ' ', u.apellido_paterno, ' ', u.apellido_materno,
//         v.lugar,
//         v.descripcion
//       FROM 
//         voluntariados v
//       JOIN 
//         usuarios u ON v.id_usuario = u.id
//       WHERE 
//         u.id = $1 AND u.tipo_usuario = 'VOLUNTARIO';
//     `;
    
//     // Ejecuta la consulta SQL
//     const result = await pool.query(query, [id]);

//     // Si no se encuentran resultados
//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: 'No se encontraron voluntariados' });
//     }

//     // Si se encuentran resultados, devolverlos
//     res.json(result.rows);
//   } catch (error) {
//     // Manejo de errores
//     console.error('Error al obtener historial:', error);
//     res.status(500).json({ message: 'Error en el servidor al obtener el historial' });
//   }
// });

app.get('/voluntarios/:id/historial', async (req, res) => {
  const { id } = req.params; // Obtén el ID del voluntario de los parámetros de la URL
  try {
    const query = `
      SELECT 
        v.id AS id_voluntariado,
        v.nombre,
        CONCAT(u.nombre, ' ', u.apellido_paterno, ' ', u.apellido_materno) AS nombre_completo,
        v.lugar,
        v.descripcion,
        va.fecha_asignacion
      FROM 
        voluntariados v
      JOIN 
        voluntarios_asignados va ON v.id = va.id_voluntariado
      JOIN 
        usuarios u ON va.id_voluntario = u.id
      WHERE 
        u.id = $1; -- Filtra por el ID del voluntario
    `;
    
    // Ejecuta la consulta SQL
    const result = await pool.query(query, [id]);
    console.log(result);
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



function verificarVoluntario(req, res, next) {
  const { tipo_usuario } = req.user; // Supone que ya tienes autenticación implementada

  if (tipo_usuario !== 'VOLUNTARIO') {
    return res.status(403).json({ message: 'Acceso Restringido' });
  }
  next();
}

app.get('/voluntarios/:id/feedback', async (req, res) => {
  const { id } = req.params; // ID del voluntariado
  try {
    const query = `
      SELECT 
        fb.id AS feedback_id,
        fb.fecha AS feedback_fecha,
        fb.reconocimiento,
        fb.oportunidad_mejora,
        fb.adicional,
        fb.mentor
      FROM feedback fb
      WHERE fb.id_voluntariado = $1
      ORDER BY fb.fecha;
    `;

    const result = await pool.query(query, [id]);
    console.log(result.rows)
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontró feedback para este voluntariado' });
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener feedback:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener el feedback' });
  }
});



function authenticateToken(req, res, next) {
  const token = req.get('Authorization')?.split(' ')[1];
  console.log('Token recibido:', token); // Depuración

  if (!token) {
    console.warn('Token no proporcionado');
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'tu_secreto_secreto', (err, user) => {
    if (err) {
      console.error('Error de verificación de token:', err);
      return res.status(403).json({ message: 'Token no válido' });
    }

    console.log('Payload decodificado:', user); // Verifica el contenido del token

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
  console.log(req.user.tipo_usuario);
  console.log('Rol del usuario:', rol); // Verifica el valor del rol
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
          v.estado_voluntariado
      FROM voluntariados v
      ORDER BY v.fecha_inicio DESC;
    `;

    const result = await pool.query(query); // Ejecuta la consulta
    console.log('Resultado de la consulta:', result.rows); 
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

app.post('/voluntariados', authenticateToken, async (req, res) => {
  const {
    nombre,
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

  const id_usuario = req.user.id; // Extraer el id del token

  if (!id_usuario) {
    return res.status(401).json({ message: 'El usuario no está autenticado.' });
  }

  // Validar campos obligatorios
  if (!nombre || !tipo || !fecha_inicio || !fecha_fin || !objetivoGeneral || !publicoObjetivo) {
    return res.status(400).json({ message: 'Faltan datos obligatorios' });
  }

  try {
    const query = `
      INSERT INTO voluntariados (
        nombre, tipo, fecha_inicio, fecha_cierre_proyectada, objetivo_general,
        objetivo_especifico1, objetivo_especifico2, objetivo_especifico3,
        objetivo_especifico4, objetivo_especifico5, publico_objetivo,
        beneficiarios_directos, beneficiarios_indirectos, presupuesto_inicial, aliados, id_usuario
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING *;
    `;

    const values = [
      nombre,
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
      id_usuario, // Usar el id del token
    ];

    console.log('Valores de la consulta:', values);

    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error al crear voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor al crear voluntariado', error: error.message });
  }
});


// Obtener un voluntariado por ID
app.get('/voluntariados/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  console.log('Usuario autenticado:', req.user); // Verifica el usuario autenticado

  try {
    const query = 'SELECT * FROM voluntariados WHERE id = $1';
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.warn('Voluntariado no encontrado:', id);
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener voluntariado:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Actualizar un voluntariado
app.put('/voluntariados/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  console.log("ID recibido para actualización:", id);

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

    console.log("Valores enviados al query:", values);

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Voluntariado no encontrado' });
    }

    console.log("Registro actualizado:", result.rows[0]);

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


app.get('/voluntariados/voluntarios/no-asignados', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT u.id, CONCAT(u.nombre, ' ', u.apellido_paterno, ' ', u.apellido_materno) AS nombre_completo
      FROM usuarios u
      LEFT JOIN voluntarios_asignados va ON u.id = va.id_voluntario
      WHERE u.tipo_usuario = 'VOLUNTARIO'
        AND va.id_voluntariado IS NULL;
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



app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});