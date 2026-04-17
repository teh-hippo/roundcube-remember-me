<?php

/**
 * Remember Me plugin for Roundcube.
 *
 * Adds a "Remember Me" checkbox to the login form. When checked, the plugin
 * stores an encrypted auth token so the user is automatically logged in on
 * subsequent visits without seeing the login form.
 *
 * Also supports autologin mode for single-tenant deployments gated by an
 * outer auth layer (e.g. Home Assistant Ingress).
 *
 * Security notes:
 *  - Only a SHA-256 hash of the token is stored server-side.
 *  - The IMAP password is encrypted with Roundcube's des_key.
 *  - Tokens are single-use (rotated on each auto-login).
 *  - Stale tokens are purged on startup.
 *
 * @author  teh-hippo
 * @license MIT
 */
class roundcube_remember_me extends rcube_plugin
{
    public $task = 'login|logout|mail';

    /** @var rcmail */
    private $rc;

    /** @var bool */
    private $table_checked = false;

    /**
     * Plugin initialisation.
     */
    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config('config.inc.php.dist');
        $this->load_config();
        $this->add_texts('localization/', true);

        $task = $this->rc->task ?? 'unknown';
        rcube::console("remember_me: init() called, task={$task}");

        // Auto-login: either from config (operator-provisioned) or from
        // a stored remember-me token. Runs on every request.
        $this->add_hook('startup', [$this, 'on_startup']);

        // Inject "Remember Me" checkbox into the login form.
        $this->add_hook('template_object_loginform', [$this, 'on_login_form']);

        // After successful login, store a token if "Remember Me" was checked.
        $this->add_hook('login_after', [$this, 'on_login_after']);

        // On logout, clear the cookie and stored token.
        $this->add_hook('logout_after', [$this, 'on_logout_after']);
    }

    // =========================================================================
    // Startup — auto-login from config or stored token
    // =========================================================================

    /**
     * Startup hook. If no active session, attempt auto-login via:
     *  1. Operator-provisioned credentials (autologin config)
     *  2. Stored remember-me token (cookie)
     */
    public function on_startup($args)
    {
        // Already authenticated — nothing to do.
        if (!empty($_SESSION['user_id'])) {
            return $args;
        }

        rcube::console("remember_me: startup hook, no session, task={$args['task']}");

        // Let the user submit the form themselves if they are mid-login.
        if ($args['task'] === 'login' && $args['action'] === 'login'
            && $_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['_user'])) {
            return $args;
        }

        // 1. Try operator-provisioned autologin.
        // Skip if the user just explicitly logged out (suppression cookie).
        if ($this->rc->config->get('remember_me_autologin')
            && empty($_COOKIE['rc_remember_me_suppress'])) {
            $user = $this->rc->config->get('remember_me_autologin_user');
            $pass = $this->rc->config->get('remember_me_autologin_pass');
            if ($user && $pass) {
                $host = $this->resolve_imap_host();
                if ($this->do_login($user, $pass, $host)) {
                    return $args;
                }
            }
        }

        // 2. Try remember-me cookie.
        if (!$this->rc->config->get('remember_me_enabled', true)) {
            return $args;
        }

        $cookie_token = $_COOKIE['rc_remember_me'] ?? null;
        if (!$cookie_token) {
            return $args;
        }

        $token_hash = hash('sha256', $cookie_token);
        $row = $this->token_lookup($token_hash);

        if (!$row) {
            $this->clear_cookie();
            return $args;
        }

        // Decrypt the stored password.
        $password = $this->rc->decrypt($row['password']);
        if (!$password) {
            $this->token_delete($token_hash);
            $this->clear_cookie();
            return $args;
        }

        // Check token expiry.
        $lifetime = (int) $this->rc->config->get('remember_me_lifetime', 2592000);
        if ((time() - (int) $row['created_at']) > $lifetime) {
            $this->token_delete($token_hash);
            $this->clear_cookie();
            return $args;
        }

        $host = $row['host'];
        $user = $row['username'];

        if ($this->do_login($user, $password, $host)) {
            // Rotate the token (single-use).
            $this->token_delete($token_hash);
            $this->store_token($user, $password, $host);
        } else {
            // Login failed — credentials changed or IMAP is down. Clear.
            $this->token_delete($token_hash);
            $this->clear_cookie();
        }

        return $args;
    }

    // =========================================================================
    // Login form — inject "Remember Me" checkbox
    // =========================================================================

    /**
     * Inject a "Remember Me" checkbox below the login form fields.
     */
    public function on_login_form($args)
    {
        if (!$this->rc->config->get('remember_me_enabled', true)) {
            return $args;
        }

        $checkbox_html = '<div class="form-group form-check" style="margin: 0.5em 0;">'
            . '<label>'
            . '<input type="checkbox" name="_remember_me" id="rcmRememberMe" value="1" /> '
            . rcube_utils::rep_specialchars_output($this->gettext('remember_me'))
            . '</label>'
            . '</div>';

        $args['content'] .= $checkbox_html;
        return $args;
    }

    // =========================================================================
    // After login — store token if "Remember Me" was checked
    // =========================================================================

    /**
     * After a successful login, if the "Remember Me" checkbox was ticked,
     * generate a token and store encrypted credentials.
     */
    public function on_login_after($args)
    {
        if (!$this->rc->config->get('remember_me_enabled', true)) {
            return $args;
        }

        $remember = rcube_utils::get_input_string('_remember_me', rcube_utils::INPUT_POST);
        if (!$remember) {
            return $args;
        }

        // Retrieve the credentials that were just used to log in.
        $user = $args['user'] ?? $_SESSION['username'] ?? null;
        $pass = $args['pass'] ?? null;

        // Roundcube encrypts the password in session early — try to get the
        // plaintext from the POST if the hook args don't carry it.
        if (!$pass) {
            $pass = rcube_utils::get_input_string('_pass', rcube_utils::INPUT_POST);
        }

        $host = $args['host'] ?? $_SESSION['storage_host'] ?? $this->resolve_imap_host();

        if (!$user || !$pass) {
            return $args;
        }

        $this->store_token($user, $pass, $host);
        return $args;
    }

    // =========================================================================
    // Logout — clear cookie + stored token
    // =========================================================================

    /**
     * On logout, remove the remember-me cookie and delete the stored token.
     * Sets a short-lived suppression cookie to prevent autologin from
     * immediately re-logging the user in on the post-logout redirect.
     */
    public function on_logout_after($args)
    {
        rcube::console("remember_me: logout_after hook fired");
        $cookie_token = $_COOKIE['rc_remember_me'] ?? null;
        if ($cookie_token) {
            $token_hash = hash('sha256', $cookie_token);
            $this->token_delete($token_hash);
            rcube::console("remember_me: deleted token from DB");
        }
        $this->clear_cookie();
        rcube::console("remember_me: cleared cookie");

        // Suppress autologin for 10 seconds so the logout redirect lands on
        // the login form instead of being immediately re-authenticated.
        $path = $this->rc->config->get('request_path', '/');
        setcookie('rc_remember_me_suppress', '1', [
            'expires'  => time() + 10,
            'path'     => $path,
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Lax',
        ]);

        // Purge expired tokens while we're at it.
        $this->token_purge_expired();

        return $args;
    }

    // =========================================================================
    // Login helper
    // =========================================================================

    /**
     * Perform a login and complete the session ritual.
     *
     * @return bool true on success
     */
    private function do_login(string $user, string $pass, string $host): bool
    {
        if ($this->rc->login($user, $pass, $host, true)) {
            $this->rc->session->remove('temp');
            $this->rc->session->regenerate_id(false);
            $this->rc->session->set_auth_cookie();
            $this->rc->log_login();

            $this->rc->output->redirect(['_task' => 'mail']);
            return true;
        }

        rcube::raise_error([
            'code'    => 500,
            'file'    => __FILE__,
            'line'    => __LINE__,
            'message' => "remember_me: login failed for user={$user} host={$host}",
        ], true, false);

        return false;
    }

    // =========================================================================
    // Token storage (SQLite via Roundcube DB abstraction)
    // =========================================================================

    /**
     * Ensure the remember_me_tokens table exists.
     */
    private function ensure_table(): void
    {
        if ($this->table_checked) {
            return;
        }

        $this->rc->db->query(
            "CREATE TABLE IF NOT EXISTS remember_me_tokens ("
            . "token_hash TEXT PRIMARY KEY,"
            . "username TEXT NOT NULL,"
            . "password TEXT NOT NULL,"
            . "host TEXT NOT NULL,"
            . "created_at INTEGER NOT NULL"
            . ")"
        );

        $this->table_checked = true;
    }

    /**
     * Store a new remember-me token and set the cookie.
     */
    private function store_token(string $username, string $password, string $host): void
    {
        $this->ensure_table();

        $raw_token  = bin2hex(random_bytes(32));
        $token_hash = hash('sha256', $raw_token);
        $enc_pass   = $this->rc->encrypt($password);

        $this->rc->db->query(
            "INSERT INTO remember_me_tokens (token_hash, username, password, host, created_at)"
            . " VALUES (?, ?, ?, ?, ?)",
            $token_hash,
            $username,
            $enc_pass,
            $host,
            time()
        );

        $this->set_cookie($raw_token);
    }

    /**
     * Look up a token by its hash.
     *
     * @return array|null {token_hash, username, password, host, created_at}
     */
    private function token_lookup(string $token_hash): ?array
    {
        $this->ensure_table();

        $result = $this->rc->db->query(
            "SELECT * FROM remember_me_tokens WHERE token_hash = ?",
            $token_hash
        );

        $row = $this->rc->db->fetch_assoc($result);
        return $row ?: null;
    }

    /**
     * Delete a token by its hash.
     */
    private function token_delete(string $token_hash): void
    {
        $this->ensure_table();

        $this->rc->db->query(
            "DELETE FROM remember_me_tokens WHERE token_hash = ?",
            $token_hash
        );
    }

    /**
     * Purge tokens older than the configured lifetime.
     */
    private function token_purge_expired(): void
    {
        $this->ensure_table();

        $lifetime = (int) $this->rc->config->get('remember_me_lifetime', 2592000);
        $cutoff = time() - $lifetime;

        $this->rc->db->query(
            "DELETE FROM remember_me_tokens WHERE created_at < ?",
            $cutoff
        );
    }

    // =========================================================================
    // Cookie helpers
    // =========================================================================

    /**
     * Set the remember-me cookie.
     */
    private function set_cookie(string $token): void
    {
        $lifetime = (int) $this->rc->config->get('remember_me_lifetime', 2592000);
        $path = $this->rc->config->get('request_path', '/');

        setcookie('rc_remember_me', $token, [
            'expires'  => time() + $lifetime,
            'path'     => $path,
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Clear the remember-me cookie.
     */
    private function clear_cookie(): void
    {
        $path = $this->rc->config->get('request_path', '/');

        setcookie('rc_remember_me', '', [
            'expires'  => time() - 3600,
            'path'     => $path,
            'secure'   => true,
            'httponly'  => true,
            'samesite' => 'Lax',
        ]);

        unset($_COOKIE['rc_remember_me']);
    }

    // =========================================================================
    // Host resolution
    // =========================================================================

    /**
     * Resolve the default IMAP host from config.
     * Roundcube 1.6+ uses `imap_host`; older versions used `default_host`.
     */
    private function resolve_imap_host(): string
    {
        $host = $this->rc->config->get('imap_host');
        if (empty($host)) {
            $host = $this->rc->config->get('default_host');
        }
        if (is_array($host)) {
            $host = $host[0] ?? array_values($host)[0] ?? 'localhost';
        }
        return $host ?: 'localhost';
    }
}
