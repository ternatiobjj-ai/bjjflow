import { Router } from 'express';
import { UsersController } from '../controllers/usersController';
import { requireAdmin } from '../middleware/authMiddleware';

const router = Router();

// Todas as operações de usuários são restritas a administradores autenticados
router.get('/', requireAdmin, UsersController.listUsers);
router.post('/:id/approve', requireAdmin, UsersController.approveUser);
router.patch('/:id/role', requireAdmin, UsersController.updateRole);

export default router;

