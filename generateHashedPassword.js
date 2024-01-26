const bcrypt = require('bcrypt');

const password = 'alohomora.123';
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error al generar la contraseña cifrada:', err);
  } else {
    console.log('Contraseña cifrada:', hash);
  }
});
