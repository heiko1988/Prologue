<?php

class UpdateController extends Controller {

    private const UPDATE_LOCK_TTL_SECONDS = 120;
    private const UPDATE_LOCK_FILENAME = 'db_update.lock';

    /**
     * Map of version => SQL statements to run when migrating TO that version.
     * Add entries here for each new version that requires schema changes.
     * Versions below 0.0.3 are intentionally empty — no installs exist at those versions.
     */
    private static function getMigrations(): array {
        return [
            '0.0.6' => [
                "ALTER TABLE attachments ADD COLUMN file_hash CHAR(64) NULL AFTER height, ADD COLUMN dedup_source_id BIGINT NULL AFTER file_hash, ADD KEY idx_attachments_hash (file_hash, file_extension)",
                "ALTER TABLE attachments ADD CONSTRAINT fk_attachments_dedup_source FOREIGN KEY (dedup_source_id) REFERENCES attachments(id) ON DELETE SET NULL",
            ],
            '0.1.0' => [
                "CREATE TABLE IF NOT EXISTS roles (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50) NOT NULL UNIQUE, color VARCHAR(7) NOT NULL DEFAULT '#6b7280', description VARCHAR(255) DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
                "CREATE TABLE IF NOT EXISTS user_roles (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, role_id INT NOT NULL, assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY uq_user_role (user_id, role_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
                "CREATE TABLE IF NOT EXISTS chat_temp_access (id INT AUTO_INCREMENT PRIMARY KEY, chat_id INT NOT NULL, user_id INT NOT NULL, granted_by INT DEFAULT NULL, expires_at DATETIME DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY uq_chat_temp_access (chat_id, user_id), FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
                "ALTER TABLE chats ADD COLUMN required_role_id INT DEFAULT NULL, ADD CONSTRAINT fk_chats_required_role FOREIGN KEY (required_role_id) REFERENCES roles(id) ON DELETE SET NULL",
            ],
            '0.1.1' => [
                "ALTER TABLE roles ADD COLUMN position INT NOT NULL DEFAULT 0 AFTER description, ADD COLUMN can_kick TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_ban TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_mute TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_pin TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_rename_chat TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_manage_channels TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_assign_roles TINYINT(1) NOT NULL DEFAULT 0, ADD COLUMN can_move_users TINYINT(1) NOT NULL DEFAULT 0",
                "CREATE TABLE IF NOT EXISTS chat_bans (id INT AUTO_INCREMENT PRIMARY KEY, chat_id INT NOT NULL, user_id INT NOT NULL, banned_by INT DEFAULT NULL, reason VARCHAR(255) DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY uq_chat_ban (chat_id, user_id), FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
                "ALTER TABLE roles ADD INDEX idx_roles_position (position DESC)",
            ],
            '0.1.2' => [
                "ALTER TABLE messages ADD COLUMN edited_at TIMESTAMP NULL DEFAULT NULL AFTER created_at",
                "ALTER TABLE messages ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL AFTER edited_at",
            ],
        ];
    }

    private function getUpdateLockPath(): string {
        return rtrim((string)APP_LOG_DIRECTORY, '/') . '/' . self::UPDATE_LOCK_FILENAME;
    }

    private function getRemainingLockSeconds(): int {
        $path = $this->getUpdateLockPath();
        if (!is_file($path)) {
            return 0;
        }

        $startedAt = (int)trim((string)@file_get_contents($path));
        if ($startedAt <= 0) {
            return 0;
        }

        $elapsed = time() - $startedAt;
        if ($elapsed >= self::UPDATE_LOCK_TTL_SECONDS) {
            return 0;
        }

        return self::UPDATE_LOCK_TTL_SECONDS - $elapsed;
    }

    private function tryAcquireUpdateLock(): int {
        $logDirectory = rtrim((string)APP_LOG_DIRECTORY, '/');
        if (!is_dir($logDirectory)) {
            @mkdir($logDirectory, 0755, true);
        }

        $path = $this->getUpdateLockPath();
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            return 0;
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return 0;
            }

            rewind($handle);
            $existingValue = stream_get_contents($handle);
            $startedAt = (int)trim((string)$existingValue);

            if ($startedAt > 0) {
                $elapsed = time() - $startedAt;
                if ($elapsed < self::UPDATE_LOCK_TTL_SECONDS) {
                    return self::UPDATE_LOCK_TTL_SECONDS - $elapsed;
                }
            }

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, (string)time());
            fflush($handle);

            return 0;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function renderUpdateView(string $dbVersion, ?string $errorMessage = null): void {
        $lockRemaining = $this->getRemainingLockSeconds();

        $this->viewRaw('update', [
            'csrf'          => $this->csrfToken(),
            'dbVersion'     => $dbVersion,
            'appVersion'    => APP_VERSION,
            'errorMessage'  => $errorMessage,
            'lockRemaining' => $lockRemaining,
        ]);
    }

    public function showUpdate() {
        $dbVersion = Setting::get('database_version') ?? '0.0.0';

        if (version_compare($dbVersion, APP_VERSION, '>=')) {
            ErrorHandler::abort(404);
        }

        $this->renderUpdateView($dbVersion);
    }

    public function runUpdate() {
        Auth::csrfValidate();

        $dbVersion = Setting::get('database_version') ?? '0.0.0';

        if (version_compare($dbVersion, APP_VERSION, '>=')) {
            ErrorHandler::abort(404);
        }

        $lockRemaining = $this->tryAcquireUpdateLock();
        if ($lockRemaining > 0) {
            $this->renderUpdateView(
                $dbVersion,
                'Another update attempt is already in progress. Please try again in about ' . $lockRemaining . ' seconds.'
            );
            return;
        }

        $migrations = self::getMigrations();
        $versions = array_keys($migrations);
        usort($versions, 'version_compare');

        $pdo = Database::getInstance();

        try {
            $pdo->beginTransaction();

            foreach ($versions as $version) {
                if (version_compare($version, APP_VERSION, '>')) {
                    continue;
                }

                if (version_compare($dbVersion, $version, '<')) {
                    foreach ($migrations[$version] as $sql) {
                        Database::query($sql);
                    }
                    Setting::set('database_version', $version);
                    $dbVersion = $version;
                }
            }

            // Advance DB version to app version even if no schema migrations were needed
            if (version_compare($dbVersion, APP_VERSION, '<')) {
                Setting::set('database_version', APP_VERSION);
            }

            if ($pdo->inTransaction()) {
                $pdo->commit();
            }
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            $this->renderUpdateView($dbVersion, 'Update failed at version ' . $dbVersion . ': ' . $e->getMessage());
            return;
        }

        $this->flash('success', 'update_complete');
        $this->redirect('/');
    }
}
