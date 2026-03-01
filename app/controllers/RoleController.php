<?php
class RoleController extends Controller {

    private function requireAdminUser() {
        Auth::requireAuth();
        $user = Auth::user();
        if (!$user || strtolower((string)($user->role ?? '')) !== 'admin') {
            ErrorHandler::abort(403, 'Access denied');
        }
        return $user;
    }

    public function list() {
        Auth::requireAuth();
        $roles = Role::all();
        $this->json(['roles' => $roles]);
    }

    public function create() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $name = trim((string)($_POST['name'] ?? ''));
        $color = trim((string)($_POST['color'] ?? '#6b7280'));
        $description = trim((string)($_POST['description'] ?? ''));

        if ($name === '' || mb_strlen($name) > 50) {
            $this->json(['error' => 'Role name is required (max 50 characters)'], 400);
        }

        if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
            $color = '#6b7280';
        }

        $existing = Role::findByName($name);
        if ($existing) {
            $this->json(['error' => 'A role with this name already exists'], 409);
        }

        $position = (int)($_POST['position'] ?? 0);
        $permissions = [];
        foreach (['can_kick','can_ban','can_mute','can_pin','can_rename_chat','can_manage_channels','can_assign_roles','can_move_users'] as $p) {
            $permissions[$p] = (int)($_POST[$p] ?? 0);
        }

        $id = Role::create($name, $color, $description !== '' ? $description : null, $position, $permissions);
        $role = Role::find($id);

        $this->json(['success' => true, 'role' => $role]);
    }

    public function update() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $id = (int)($_POST['id'] ?? 0);
        $name = trim((string)($_POST['name'] ?? ''));
        $color = trim((string)($_POST['color'] ?? '#6b7280'));
        $description = trim((string)($_POST['description'] ?? ''));

        if ($id <= 0) {
            $this->json(['error' => 'Invalid role ID'], 400);
        }

        $role = Role::find($id);
        if (!$role) {
            $this->json(['error' => 'Role not found'], 404);
        }

        if ($name === '' || mb_strlen($name) > 50) {
            $this->json(['error' => 'Role name is required (max 50 characters)'], 400);
        }

        if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
            $color = '#6b7280';
        }

        $existingByName = Role::findByName($name);
        if ($existingByName && (int)$existingByName->id !== $id) {
            $this->json(['error' => 'A role with this name already exists'], 409);
        }

        $position = (int)($_POST['position'] ?? 0);
        $permissions = [];
        foreach (['can_kick','can_ban','can_mute','can_pin','can_rename_chat','can_manage_channels','can_assign_roles','can_move_users'] as $p) {
            $permissions[$p] = (int)($_POST[$p] ?? 0);
        }

        Role::update($id, $name, $color, $description !== '' ? $description : null, $position, $permissions);
        $role = Role::find($id);

        $this->json(['success' => true, 'role' => $role]);
    }

    public function delete() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0) {
            $this->json(['error' => 'Invalid role ID'], 400);
        }

        $role = Role::find($id);
        if (!$role) {
            $this->json(['error' => 'Role not found'], 404);
        }

        Role::delete($id);
        $this->json(['success' => true]);
    }

    public function assign() {
        Auth::requireAuth();
        Auth::csrfValidate();

        $actorUser = Auth::user();
        $isAdmin = Auth::isAdmin($actorUser);

        $userId = (int)($_POST['user_id'] ?? 0);
        $roleId = (int)($_POST['role_id'] ?? 0);

        if ($userId <= 0 || $roleId <= 0) {
            $this->json(['error' => 'Invalid user or role ID'], 400);
        }

        // Non-admin needs can_assign_roles + higher position than the role
        if (!$isAdmin) {
            if (!Auth::hasPermission('can_assign_roles', $actorUser)) {
                $this->json(['error' => 'Access denied'], 403);
            }
            if (!Role::canManageRole((int)$actorUser->id, $roleId)) {
                $this->json(['error' => 'You cannot assign a role at or above your own level'], 403);
            }
        }

        $user = User::find($userId);
        if (!$user) {
            $this->json(['error' => 'User not found'], 404);
        }

        $role = Role::find($roleId);
        if (!$role) {
            $this->json(['error' => 'Role not found'], 404);
        }

        Role::assignToUser($userId, $roleId);
        $this->json(['success' => true]);
    }

    public function remove() {
        Auth::requireAuth();
        Auth::csrfValidate();

        $actorUser = Auth::user();
        $isAdmin = Auth::isAdmin($actorUser);

        $userId = (int)($_POST['user_id'] ?? 0);
        $roleId = (int)($_POST['role_id'] ?? 0);

        if ($userId <= 0 || $roleId <= 0) {
            $this->json(['error' => 'Invalid user or role ID'], 400);
        }

        // Non-admin needs can_assign_roles + higher position than the role
        if (!$isAdmin) {
            if (!Auth::hasPermission('can_assign_roles', $actorUser)) {
                $this->json(['error' => 'Access denied'], 403);
            }
            if (!Role::canManageRole((int)$actorUser->id, $roleId)) {
                $this->json(['error' => 'You cannot remove a role at or above your own level'], 403);
            }
        }

        Role::removeFromUser($userId, $roleId);
        $this->json(['success' => true]);
    }

    public function setChatRole() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $chatId = (int)($_POST['chat_id'] ?? 0);
        // Support both single role_id and multiple role_ids[]
        $roleIds = $_POST['role_ids'] ?? null;
        if ($roleIds === null) {
            $singleId = (int)($_POST['role_id'] ?? 0);
            $roleIds = $singleId > 0 ? [$singleId] : [];
        }
        if (!is_array($roleIds)) {
            $roleIds = array_map('intval', explode(',', (string)$roleIds));
        }
        $roleIds = array_filter(array_map('intval', $roleIds), fn($id) => $id > 0);

        if ($chatId <= 0) {
            $this->json(['error' => 'Invalid chat ID'], 400);
        }

        $chat = Database::query("SELECT id, type FROM chats WHERE id = ?", [$chatId])->fetch();
        if (!$chat) {
            $this->json(['error' => 'Chat not found'], 404);
        }

        if (!Chat::isGroupType($chat->type ?? null)) {
            $this->json(['error' => 'Roles can only be assigned to group chats'], 400);
        }

        // Validate all role IDs
        foreach ($roleIds as $rid) {
            $role = Role::find($rid);
            if (!$role) {
                $this->json(['error' => 'Role not found: ' . $rid], 404);
            }
        }

        Role::setChatRequiredRoles($chatId, $roleIds);
        $this->json(['success' => true]);
    }

    public function removeChatRole() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $chatId = (int)($_POST['chat_id'] ?? 0);
        if ($chatId <= 0) {
            $this->json(['error' => 'Invalid chat ID'], 400);
        }

        Role::setChatRole($chatId, null);
        $this->json(['success' => true]);
    }

    public function grantTempAccess() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $chatId = (int)($_POST['chat_id'] ?? 0);
        $userId = (int)($_POST['user_id'] ?? 0);
        $duration = trim((string)($_POST['duration'] ?? ''));
        $adminUser = Auth::user();

        if ($chatId <= 0 || $userId <= 0) {
            $this->json(['error' => 'Invalid chat or user ID'], 400);
        }

        $user = User::find($userId);
        if (!$user) {
            $this->json(['error' => 'User not found'], 404);
        }

        $expiresAt = null;
        switch ($duration) {
            case '1h':
                $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));
                break;
            case '24h':
                $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));
                break;
            case '7d':
                $expiresAt = date('Y-m-d H:i:s', strtotime('+7 days'));
                break;
            case 'unlimited':
            case '':
                $expiresAt = null;
                break;
            default:
                $this->json(['error' => 'Invalid duration'], 400);
        }

        Role::grantTempAccess($chatId, $userId, (int)$adminUser->id, $expiresAt);

        // Auto-add as chat member if not already
        Database::query(
            "INSERT IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)",
            [$chatId, $userId]
        );

        $this->json(['success' => true]);
    }

    public function revokeTempAccess() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $chatId = (int)($_POST['chat_id'] ?? 0);
        $userId = (int)($_POST['user_id'] ?? 0);

        if ($chatId <= 0 || $userId <= 0) {
            $this->json(['error' => 'Invalid chat or user ID'], 400);
        }

        Role::revokeTempAccess($chatId, $userId);
        $this->json(['success' => true]);
    }

    public function getTempAccess() {
        $this->requireAdminUser();

        $chatId = (int)($_GET['chat_id'] ?? 0);
        if ($chatId <= 0) {
            $this->json(['error' => 'Invalid chat ID'], 400);
        }

        $list = Role::getTempAccessList($chatId);
        $this->json(['temp_access' => $list]);
    }

    public function getUserRoles() {
        Auth::requireAuth();

        $userId = (int)($_GET['user_id'] ?? 0);
        if ($userId <= 0) {
            $this->json(['error' => 'Invalid user ID'], 400);
        }

        $roles = Role::getUserRoles($userId);
        $this->json(['roles' => $roles]);
    }

    public function getUserTempAccess() {
        $this->requireAdminUser();

        $userId = (int)($_GET['user_id'] ?? 0);
        if ($userId <= 0) {
            $this->json(['error' => 'Invalid user ID'], 400);
        }

        $list = Role::getTempAccessListByUser($userId);
        $this->json(['temp_access' => $list]);
    }

    public function banFromChat() {
        Auth::requireAuth();
        Auth::csrfValidate();

        $actorUser = Auth::user();
        $chatId = (int)($_POST['chat_id'] ?? 0);
        $userId = (int)($_POST['user_id'] ?? 0);
        $reason = trim((string)($_POST['reason'] ?? ''));

        if ($chatId <= 0 || $userId <= 0) {
            $this->json(['error' => 'Invalid payload'], 400);
        }

        // Self-ban prevention
        if ((int)$actorUser->id === $userId) {
            $this->json(['error' => 'You cannot ban yourself'], 403);
        }

        // Check can_ban permission + hierarchy
        $isAdmin = Auth::isAdmin($actorUser);
        if (!$isAdmin) {
            if (!Auth::hasPermission('can_ban', $actorUser)) {
                $this->json(['error' => 'You do not have permission to ban users'], 403);
            }
            if (!Auth::canManageUser($userId, $actorUser)) {
                $this->json(['error' => 'You cannot ban a user with equal or higher role'], 403);
            }
        }

        // Cannot ban the chat owner
        $chat = Database::query("SELECT created_by FROM chats WHERE id = ?", [$chatId])->fetch();
        if ($chat && (int)($chat->created_by ?? 0) === $userId) {
            $this->json(['error' => 'Cannot ban the group owner'], 403);
        }

        Role::banUserFromChat($chatId, $userId, (int)$actorUser->id, $reason !== '' ? $reason : null);
        $this->json(['success' => true]);
    }

    public function unbanFromChat() {
        Auth::requireAuth();
        Auth::csrfValidate();

        $actorUser = Auth::user();
        $chatId = (int)($_POST['chat_id'] ?? 0);
        $userId = (int)($_POST['user_id'] ?? 0);

        if ($chatId <= 0 || $userId <= 0) {
            $this->json(['error' => 'Invalid payload'], 400);
        }

        $isAdmin = Auth::isAdmin($actorUser);
        if (!$isAdmin && !Auth::hasPermission('can_ban', $actorUser)) {
            $this->json(['error' => 'You do not have permission to unban users'], 403);
        }

        Role::unbanUserFromChat($chatId, $userId);
        $this->json(['success' => true]);
    }

    public function getChatBans() {
        Auth::requireAuth();

        $chatId = (int)($_GET['chat_id'] ?? 0);
        if ($chatId <= 0) {
            $this->json(['error' => 'Invalid chat ID'], 400);
        }

        $actorUser = Auth::user();
        $isAdmin = Auth::isAdmin($actorUser);
        if (!$isAdmin && !Auth::hasPermission('can_ban', $actorUser)) {
            $this->json(['error' => 'Access denied'], 403);
        }

        $bans = Role::getChatBans($chatId);
        $this->json(['bans' => $bans]);
    }
}
