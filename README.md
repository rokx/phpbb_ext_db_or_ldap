# phpBB Extension - DB or LDAP Login

This phpBB extension provides an authentication provider, which enables to use db and LDAP authentication simulaneously.

Access to the ACP remains with username and password combination.

## Requirements

* on phpBB 3.3 it works
* working LDAP authentication

## Quick Install

You can install this on the latest release of phpBB by following the steps below:

* Create `rokx/dborldap` in the `ext` directory.
* Download and unpack the repository into `ext/rokx/dborldap`
* Enable `Db Ldap Login` in the ACP at `Customise -> Manage extensions`.
* Chose Db_or_ldap in the ACP. (General Client Communication > Authenication)

## Uninstall

* Disable `Email Login` in the ACP at `Customise -> Extension Management -> Extensions`.
* To permanently uninstall, click `Delete Data`. Optionally delete the `/ext/marttiphpbb/emaillogin` directory.

## Support

* Report bugs and other issues to the [Issue Tracker](https://github.com/rokx/phpbb_ext_db_or_ldap/issues).

## License

[GPL-2.0](license.txt)
