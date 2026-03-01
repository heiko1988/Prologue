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

        $id = Role::create($name, $color, $description !== '' ? $description : null);
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

        Role::update($id, $name, $color, $description !== '' ? $description : null);
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
        $this->requireAdminUser();
        Auth::csrfValidate();

        $userId = (int)($_POST['user_id'] ?? 0);
        $roleId = (int)($_POST['role_id'] ?? 0);

        if ($userId <= 0 || $roleId <= 0) {
            $this->json(['error' => 'Invalid user or role ID'], 400);
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
        $this->requireAdminUser();
        Auth::csrfValidate();

        $userId = (int)($_POST['user_id'] ?? 0);
        $roleId = (int)($_POST['role_id'] ?? 0);

        if ($userId <= 0 || $roleId <= 0) {
            $this->json(['error' => 'Invalid user or role ID'], 400);
        }

        Role::removeFromUser($userId, $roleId);
        $this->json(['success' => true]);
    }

    public function setChatRole() {
        $this->requireAdminUser();
        Auth::csrfValidate();

        $chatId = (int)($_POST['chat_id'] ?? 0);
        $roleId = (int)($_POST['role_id'] ?? 0);

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

        if ($roleId > 0) {
            $role = Role::find($roleId);
            if (!$role) {
                $this->json(['error' => 'Role not found'], 404);
            }
        }

        Role::setChatRole($chatId, $roleId > 0 ? $roleId : null);
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
}
