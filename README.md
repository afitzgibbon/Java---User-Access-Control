# Java---User-Access-Control
This repo is intended to be a collection of classes for User &amp; Password creation and User Administration.

- added: security/Password, security/SecurityPolicy
  - enables secure password creation, restoration and renewal

- added: user/User
  - encapsulates user data

- added: login/AbstractLogin, login/LoginRequest, login/LoginResponse, login/LoginServer
  - this is a simple framework/api to build login programs

- added: ui/console/ConsoleLogin
  - a console implementation of AbstractLogin
  
- fixed: Bug #1 & #2; see 'Pull requests' -> 'closed' for details

- added: test/PasswordTest.java
  - a test program for Password
  - discovered 'Bug #3'; see 'Pull requests' -> 'closed'
  - fixed: Bug #3
