const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'bdKururay',
  password: 'alohomora',
  port: 5432,
});

async function updateVoluntariosPasswords() {
  try {
    // Seleccionar voluntarios con contraseñas NULL, vacías o espacios en blanco
    const voluntarios = await pool.query(`
      SELECT id, dni 
      FROM voluntarios 
      WHERE password IS NULL 
         OR password = '' 
         OR TRIM(password) = ''
    `);

    for (const voluntario of voluntarios.rows) {
      const { id, dni } = voluntario;

      // Generar un hash del DNI
      const hashedPassword = await bcrypt.hash(dni, 10);

      // Actualizar la contraseña en la base de datos
      await pool.query('UPDATE voluntarios SET password = $1 WHERE id = $2', [hashedPassword, id]);
      console.log(`Contraseña actualizada para el voluntario ID: ${id}`);
    }

    console.log('Actualización de contraseñas completada para voluntarios.');
    process.exit();
  } catch (error) {
    console.error('Error al actualizar contraseñas de voluntarios:', error);
    process.exit(1);
  }
}

updateVoluntariosPasswords();
