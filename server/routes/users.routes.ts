import { Router } from 'express';
import { UsersController } from '../controllers/usersController';
import { requireAdmin } from '../middleware/authMiddleware';

const router = Router();

// Listagem de usuários
router.get('/', UsersController.listUsers);

// Operações protegidas (requerem privilégios de Administrador)
router.post('/:id/approve', requireAdmin, UsersController.approveUser);
router.patch('/:id/role', requireAdmin, UsersController.updateRole);

export default router;
