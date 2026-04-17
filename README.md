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

## Requirements

- Roundcube 1.6+
- PHP 8.0+

## Licence

MIT
