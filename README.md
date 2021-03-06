# phpBB Extension - DB or LDAP Login

This phpBB extension provides an authentication provider, which enables to use db and LDAP authentication simultaneously.

## Requirements

* on phpBB 3.3 it works
* working LDAP authentication

## Quick Install

You can install this on the latest release of phpBB by following the steps below:

* Create `rokx/dborldap` in the `ext` directory.
* Download and unpack the repository into `ext/rokx/dborldap`
* Enable `Db Ldap Login` in the ACP at `Customise -> Manage extensions`.
* Make sure you have a working ldap authetnication
* Chose Db_or_ldap in the ACP. (General Client Communication > Authenication)

## Uninstall

* Disable `Db Ldap Login` in the ACP at `Customise -> Extension Management -> Extensions`.
* To permanently uninstall, click `Delete Data`. Optionally delete the `/ext/rokx/dborldap` directory.

## Support

* If you are stuck logging in you can reset the authentication method in the database -> phpbb_config table -> row 'auth_method' set value back to Ldap or Db
* Report bugs and other issues to the [Issue Tracker](https://github.com/rokx/phpbb_ext_db_or_ldap/issues).

## License

[GPL-2.0](license.txt)
