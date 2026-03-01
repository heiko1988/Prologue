<?php
class Role extends Model {

    private static array $permissionColumns = [
        'can_kick', 'can_ban', 'can_mute', 'can_pin',
        'can_rename_chat', 'can_manage_channels', 'can_assign_roles', 'can_move_users'
    ];

    public static function supportsPermissions(): bool {
        static $supports = null;
        if ($supports !== null) {
            return $supports;
        }
        try {
            $result = self::query(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'roles' AND COLUMN_NAME = 'position'"
            )->fetchColumn();
            $supports = ((int)$result) > 0;
        } catch (Throwable $e) {
            $supports = false;
        }
        return $supports;
    }

    public static function all() {
        if (self::supportsPermissions()) {
            return self::query("SELECT * FROM roles ORDER BY position DESC, name ASC")->fetchAll();
        }
        return self::query("SELECT * FROM roles ORDER BY name ASC")->fetchAll();
    }

    public static function find($id) {
        return self::query("SELECT * FROM roles WHERE id = ?", [(int)$id])->fetch();
    }

    public static function findByName($name) {
        return self::query("SELECT * FROM roles WHERE name = ?", [trim((string)$name)])->fetch();
    }

    public static function create($name, $color = '#6b7280', $description = null, $position = 0, $permissions = []) {
        if (self::supportsPermissions()) {
            $cols = 'name, color, description, position';
            $vals = '?, ?, ?, ?';
            $params = [
                trim((string)$name),
                trim((string)$color),
                $description !== null ? trim((string)$description) : null,
                (int)$position
            ];
            foreach (self::$permissionColumns as $perm) {
                $cols .= ', ' . $perm;
                $vals .= ', ?';
                $params[] = !empty($permissions[$perm]) ? 1 : 0;
            }
            self::query("INSERT INTO roles ({$cols}) VALUES ({$vals})", $params);
        } else {
            self::query(
                "INSERT INTO roles (name, color, description) VALUES (?, ?, ?)",
                [trim((string)$name), trim((string)$color), $description !== null ? trim((string)$description) : null]
            );
        }
        return (int)self::db()->lastInsertId();
    }

    public static function update($id, $name, $color, $description = null, $position = null, $permissions = []) {
        if (self::supportsPermissions() && $position !== null) {
            $sql = "UPDATE roles SET name = ?, color = ?, description = ?, position = ?";
            $params = [
                trim((string)$name),
                trim((string)$color),
                $description !== null ? trim((string)$description) : null,
                (int)$position
            ];
            foreach (self::$permissionColumns as $perm) {
                $sql .= ", {$perm} = ?";
                $params[] = !empty($permissions[$perm]) ? 1 : 0;
            }
            $sql .= " WHERE id = ?";
            $params[] = (int)$id;
            self::query($sql, $params);
        } else {
            self::query(
                "UPDATE roles SET name = ?, color = ?, description = ? WHERE id = ?",
                [trim((string)$name), trim((string)$color), $description !== null ? trim((string)$description) : null, (int)$id]
            );
        }
    }

    public static function delete($id) {
        self::query("DELETE FROM roles WHERE id = ?", [(int)$id]);
    }

    // ---- Hierarchy & Permission Methods ----

    public static function getHighestUserPosition(int $userId): int {
        if (!self::supportsPermissions()) {
            return 0;
        }
        $result = self::query(
            "SELECT MAX(r.position) FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?",
            [$userId]
        )->fetchColumn();
        return (int)($result ?? 0);
    }

    public static function canManageRole(int $actorId, int $roleId): bool {
        if (!self::supportsPermissions()) {
            return false;
        }
        $role = self::find($roleId);
        if (!$role) {
            return false;
        }
        $actorPos = self::getHighestUserPosition($actorId);
        return $actorPos > (int)($role->position ?? 0);
    }

    public static function canManageUser(int $actorId, int $targetId): bool {
        if ($actorId === $targetId) {
            return false;
        }
        if (!self::supportsPermissions()) {
            return false;
        }
        $actorPos = self::getHighestUserPosition($actorId);
        $targetPos = self::getHighestUserPosition($targetId);
        return $actorPos > $targetPos;
    }

    public static function hasPermission(int $userId, string $permission): bool {
        if (!self::supportsPermissions()) {
            return false;
        }
        if (!in_array($permission, self::$permissionColumns, true)) {
            return false;
        }
        $result = self::query(
            "SELECT MAX(r.{$permission}) FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?",
            [$userId]
        )->fetchColumn();
        return ((int)($result ?? 0)) > 0;
    }

    // ---- Chat Bans ----

    public static function isUserBannedFromChat(int $chatId, int $userId): bool {
        $row = self::query(
            "SELECT id FROM chat_bans WHERE chat_id = ? AND user_id = ? LIMIT 1",
            [$chatId, $userId]
        )->fetch();
        return (bool)$row;
    }

    public static function banUserFromChat(int $chatId, int $userId, int $bannedBy, ?string $reason = null): void {
        self::query(
            "INSERT INTO chat_bans (chat_id, user_id, banned_by, reason) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE banned_by = VALUES(banned_by), reason = VALUES(reason), created_at = CURRENT_TIMESTAMP",
            [$chatId, $userId, $bannedBy, $reason]
        );
        // Remove from chat members
        self::query(
            "DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?",
            [$chatId, $userId]
        );
    }

    public static function unbanUserFromChat(int $chatId, int $userId): void {
        self::query(
            "DELETE FROM chat_bans WHERE chat_id = ? AND user_id = ?",
            [$chatId, $userId]
        );
    }

    public static function getChatBans(int $chatId): array {
        return self::query(
            "SELECT cb.*, u.username, u.user_number, b.username AS banned_by_username
             FROM chat_bans cb
             JOIN users u ON u.id = cb.user_id
             LEFT JOIN users b ON b.id = cb.banned_by
             WHERE cb.chat_id = ?
             ORDER BY cb.created_at DESC",
            [$chatId]
        )->fetchAll();
    }

    // ---- Existing methods (unchanged) ----

    public static function getUserRoles($userId) {
        if (self::supportsPermissions()) {
            return self::query(
                "SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.position DESC, r.name ASC",
                [(int)$userId]
            )->fetchAll();
        }
        return self::query(
            "SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.name ASC",
            [(int)$userId]
        )->fetchAll();
    }

    public static function getUserRoleIds($userId) {
        $roles = self::getUserRoles($userId);
        return array_map(fn($r) => (int)$r->id, $roles);
    }

    public static function assignToUser($userId, $roleId) {
        self::query(
            "INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
            [(int)$userId, (int)$roleId]
        );
        self::syncUserToChatsForRole((int)$userId, (int)$roleId);
    }

    public static function removeFromUser($userId, $roleId) {
        self::query(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
            [(int)$userId, (int)$roleId]
        );
        self::removeUserFromChatsForRole((int)$userId, (int)$roleId);
    }

    public static function syncUserToChatsForRole(int $userId, int $roleId): void {
        // Find all chats that require this role (using new multi-role table or legacy column)
        if (self::supportsChatRequiredRoles()) {
            $chats = self::query(
                "SELECT DISTINCT crr.chat_id AS id FROM chat_required_roles crr JOIN chats c ON c.id = crr.chat_id WHERE crr.role_id = ? AND c.type = 'group'",
                [$roleId]
            )->fetchAll();
        } else {
            $chats = self::query(
                "SELECT id FROM chats WHERE required_role_id = ? AND type = 'group'",
                [$roleId]
            )->fetchAll();
        }
        foreach ($chats as $chat) {
            self::query(
                "INSERT IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)",
                [(int)$chat->id, $userId]
            );
        }
    }

    public static function syncAllUsersToChat(int $chatId, int $roleId): void {
        $users = self::query(
            "SELECT user_id FROM user_roles WHERE role_id = ?",
            [$roleId]
        )->fetchAll();
        foreach ($users as $row) {
            self::query(
                "INSERT IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)",
                [$chatId, (int)$row->user_id]
            );
        }
    }

    public static function removeUserFromChatsForRole(int $userId, int $roleId): void {
        // Find all chats that require this role (using new multi-role table or legacy column)
        if (self::supportsChatRequiredRoles()) {
            $chats = self::query(
                "SELECT DISTINCT crr.chat_id AS id FROM chat_required_roles crr JOIN chats c ON c.id = crr.chat_id WHERE crr.role_id = ? AND c.type = 'group'",
                [$roleId]
            )->fetchAll();
        } else {
            $chats = self::query(
                "SELECT id FROM chats WHERE required_role_id = ? AND type = 'group'",
                [$roleId]
            )->fetchAll();
        }

        foreach ($chats as $chat) {
            $chatId = (int)$chat->id;

            // Skip if user has temp access
            if (self::hasTempAccess($chatId, $userId)) {
                continue;
            }
            // Skip if user is chat owner
            $isOwner = (int)self::query(
                "SELECT COUNT(*) FROM chats WHERE id = ? AND created_by = ?",
                [$chatId, $userId]
            )->fetchColumn();
            if ($isOwner > 0) {
                continue;
            }
            // KEY FIX: Check if user still has ANOTHER role that grants access to this chat
            if (self::userHasAnyChatRole($userId, $chatId)) {
                continue;
            }
            // User has no remaining access — remove from chat
            self::query(
                "DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?",
                [$chatId, $userId]
            );
        }
    }

    public static function userHasRole($userId, $roleId) {
        $count = (int)self::query(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?",
            [(int)$userId, (int)$roleId]
        )->fetchColumn();
        return $count > 0;
    }

    public static function setChatRole($chatId, $roleId) {
        if ($roleId === null || $roleId <= 0) {
            self::query("UPDATE chats SET required_role_id = NULL WHERE id = ?", [(int)$chatId]);
        } else {
            self::query("UPDATE chats SET required_role_id = ? WHERE id = ?", [(int)$roleId, (int)$chatId]);
            self::syncAllUsersToChat((int)$chatId, (int)$roleId);
        }
    }

    public static function getChatRole($chatId) {
        $chat = self::query("SELECT required_role_id FROM chats WHERE id = ?", [(int)$chatId])->fetch();
        if (!$chat || !$chat->required_role_id) {
            return null;
        }
        return self::find($chat->required_role_id);
    }

    public static function grantTempAccess($chatId, $userId, $grantedBy, $expiresAt = null) {
        self::query(
            "INSERT INTO chat_temp_access (chat_id, user_id, granted_by, expires_at) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE granted_by = VALUES(granted_by), expires_at = VALUES(expires_at)",
            [(int)$chatId, (int)$userId, (int)$grantedBy, $expiresAt]
        );
    }

    public static function revokeTempAccess($chatId, $userId) {
        self::query(
            "DELETE FROM chat_temp_access WHERE chat_id = ? AND user_id = ?",
            [(int)$chatId, (int)$userId]
        );
    }

    public static function hasTempAccess($chatId, $userId) {
        $row = self::query(
            "SELECT id FROM chat_temp_access WHERE chat_id = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1",
            [(int)$chatId, (int)$userId]
        )->fetch();
        return (bool)$row;
    }

    public static function getTempAccessList($chatId) {
        return self::query(
            "SELECT cta.*, u.username, u.user_number, gb.username AS granted_by_username
             FROM chat_temp_access cta
             JOIN users u ON u.id = cta.user_id
             LEFT JOIN users gb ON gb.id = cta.granted_by
             WHERE cta.chat_id = ?
             ORDER BY cta.created_at DESC",
            [(int)$chatId]
        )->fetchAll();
    }

    public static function getTempAccessListByUser($userId) {
        return self::query(
            "SELECT cta.*, c.chat_number, c.type,
                    COALESCE(c.title, '') AS chat_title,
                    gb.username AS granted_by_username
             FROM chat_temp_access cta
             JOIN chats c ON c.id = cta.chat_id
             LEFT JOIN users gb ON gb.id = cta.granted_by
             WHERE cta.user_id = ?
             ORDER BY cta.created_at DESC",
            [(int)$userId]
        )->fetchAll();
    }

    public static function supportsRoles(): bool {
        static $supports = null;
        if ($supports !== null) {
            return $supports;
        }
        $result = self::query(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'roles'"
        )->fetchColumn();
        $supports = ((int)$result) > 0;
        return $supports;
    }

    public static function supportsChatRequiredRoles(): bool {
        static $supports = null;
        if ($supports !== null) return $supports;
        try {
            $r = self::query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'chat_required_roles'")->fetchColumn();
            $supports = ((int)$r) > 0;
        } catch (Throwable $e) { $supports = false; }
        return $supports;
    }

    public static function getChatRequiredRoles(int $chatId): array {
        if (!self::supportsChatRequiredRoles()) {
            // Fallback to single role
            $role = self::getChatRole($chatId);
            return $role ? [$role] : [];
        }
        return self::query(
            "SELECT r.* FROM roles r JOIN chat_required_roles crr ON crr.role_id = r.id WHERE crr.chat_id = ? ORDER BY r.position DESC, r.name ASC",
            [$chatId]
        )->fetchAll();
    }

    public static function getChatRequiredRoleIds(int $chatId): array {
        if (!self::supportsChatRequiredRoles()) {
            $role = self::getChatRole($chatId);
            return $role ? [(int)$role->id] : [];
        }
        $rows = self::query("SELECT role_id FROM chat_required_roles WHERE chat_id = ?", [$chatId])->fetchAll();
        return array_map(fn($r) => (int)$r->role_id, $rows);
    }

    public static function setChatRequiredRoles(int $chatId, array $roleIds): void {
        if (!self::supportsChatRequiredRoles()) {
            // Fallback: use the first role
            self::setChatRole($chatId, !empty($roleIds) ? (int)$roleIds[0] : null);
            return;
        }
        // Clear existing
        self::query("DELETE FROM chat_required_roles WHERE chat_id = ?", [$chatId]);
        // Also update legacy column
        if (empty($roleIds)) {
            self::query("UPDATE chats SET required_role_id = NULL WHERE id = ?", [$chatId]);
        } else {
            self::query("UPDATE chats SET required_role_id = ? WHERE id = ?", [(int)$roleIds[0], $chatId]);
            foreach ($roleIds as $roleId) {
                $roleId = (int)$roleId;
                if ($roleId <= 0) continue;
                self::query("INSERT IGNORE INTO chat_required_roles (chat_id, role_id) VALUES (?, ?)", [$chatId, $roleId]);
                // Auto-add users with this role
                self::syncAllUsersToChat($chatId, $roleId);
            }
        }
    }

    public static function userHasAnyChatRole(int $userId, int $chatId): bool {
        if (!self::supportsChatRequiredRoles()) {
            // Fallback to single role check
            $chat = self::query("SELECT required_role_id FROM chats WHERE id = ?", [$chatId])->fetch();
            if (!$chat || !$chat->required_role_id) return true;
            return self::userHasRole($userId, (int)$chat->required_role_id);
        }
        $roleIds = self::getChatRequiredRoleIds($chatId);
        if (empty($roleIds)) return true; // No restriction
        foreach ($roleIds as $rid) {
            if (self::userHasRole($userId, $rid)) return true;
        }
        return false;
    }
}
