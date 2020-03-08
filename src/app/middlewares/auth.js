import jwt from 'jsonwebtoken';
import { promisify } from 'util';

import authConfig from '../../config/auth';

export default async (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Verificano se o Token é valido;
  if (!authHeader) {
    return res.status(401).json({ error: 'Token not provided.' });
  }

  // Aqui estamos separando com "espaço" o bearer do token; Só vamos utilizar o token;
  const [, token] = authHeader.split(' ');

  try {
    const decoded = await promisify(jwt.verify)(token, authConfig.secret);

    req.userId = decoded.id;

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid' });
  }
};
