<?php
class Role extends Model {

    public static function all() {
        return self::query("SELECT * FROM roles ORDER BY name ASC")->fetchAll();
    }

    public static function find($id) {
        return self::query("SELECT * FROM roles WHERE id = ?", [(int)$id])->fetch();
    }

    public static function findByName($name) {
        return self::query("SELECT * FROM roles WHERE name = ?", [trim((string)$name)])->fetch();
    }

    public static function create($name, $color = '#6b7280', $description = null) {
        self::query(
            "INSERT INTO roles (name, color, description) VALUES (?, ?, ?)",
            [trim((string)$name), trim((string)$color), $description !== null ? trim((string)$description) : null]
        );
        return (int)self::db()->lastInsertId();
    }

    public static function update($id, $name, $color, $description = null) {
        self::query(
            "UPDATE roles SET name = ?, color = ?, description = ? WHERE id = ?",
            [trim((string)$name), trim((string)$color), $description !== null ? trim((string)$description) : null, (int)$id]
        );
    }

    public static function delete($id) {
        self::query("DELETE FROM roles WHERE id = ?", [(int)$id]);
    }

    public static function getUserRoles($userId) {
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
        // Auto-add user to all group chats that require this role
        self::syncUserToChatsForRole((int)$userId, (int)$roleId);
    }

    public static function removeFromUser($userId, $roleId) {
        self::query(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
            [(int)$userId, (int)$roleId]
        );
        // Remove user from chats they no longer have role access to
        self::removeUserFromChatsForRole((int)$userId, (int)$roleId);
    }

    public static function syncUserToChatsForRole(int $userId, int $roleId): void {
        $chats = self::query(
            "SELECT id FROM chats WHERE required_role_id = ? AND type = 'group'",
            [$roleId]
        )->fetchAll();
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
        $chats = self::query(
            "SELECT id FROM chats WHERE required_role_id = ? AND type = 'group'",
            [$roleId]
        )->fetchAll();
        foreach ($chats as $chat) {
            // Don't remove if user has temp access or is chat owner
            if (self::hasTempAccess((int)$chat->id, $userId)) {
                continue;
            }
            $isOwner = (int)self::query(
                "SELECT COUNT(*) FROM chats WHERE id = ? AND created_by = ?",
                [(int)$chat->id, $userId]
            )->fetchColumn();
            if ($isOwner > 0) {
                continue;
            }
            self::query(
                "DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?",
                [(int)$chat->id, $userId]
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
            // Auto-add all users with this role to the chat
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
}
