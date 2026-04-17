# Roundcube Remember Me

Roundcube plugin that adds a **Remember Me** checkbox to the login form. When
checked, the plugin stores an encrypted auth token so users are automatically
logged in on subsequent visits without seeing the login form again.

Also supports **autologin** mode for single-tenant deployments gated by an
outer auth layer (e.g. Home Assistant Ingress).

## Installation

### Via Composer

```bash
composer require teh-hippo/roundcube-remember-me
```

Then add `roundcube_remember_me` to the `plugins` array in your Roundcube config.

### Manual

```bash
cd /path/to/roundcube/plugins
git clone https://github.com/teh-hippo/roundcube-remember-me.git roundcube_remember_me
```

Add `roundcube_remember_me` to `$config['plugins']` in `config/config.inc.php`.

## Configuration

See `config.inc.php.dist` for all options.

### Remember Me (default)

No configuration needed. The checkbox appears on the login form automatically.

### Autologin

```php
$config['remember_me_autologin']      = true;
$config['remember_me_autologin_user'] = 'user@example.com';
$config['remember_me_autologin_pass'] = '...';
```

## Security

- Only a SHA-256 hash of the auth token is stored server-side.
- The IMAP password is encrypted with Roundcube's `des_key`. Anyone with
  database access **and** the `des_key` can recover stored credentials.
  In the Home Assistant add-on deployment this is acceptable because the
  database is behind HA's own auth layer.
- Tokens are single-use (rotated on each auto-login).
- On logout, the cookie and stored token are both cleared.
- Autologin mode includes logout suppression to prevent immediate
  re-authentication after explicit logout.

## Requirements

- Roundcube 1.6+
- PHP 8.0+

## Licence

MIT
