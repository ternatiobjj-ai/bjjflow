import { Router } from 'express';
import { AuthController } from '../controllers/authController';

const router = Router();

// Rotas de autenticação e recuperação de credenciais
router.post('/login', AuthController.login);
router.post('/recover-password', AuthController.recoverPassword);
router.post('/change-password', AuthController.changePassword);

export default router;
